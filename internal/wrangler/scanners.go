package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/internal/nmap"
	"Wrangler/pkg/models"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	discoveryDone        atomic.Bool
	serviceEnumDone      atomic.Bool
	staticScannersDone   atomic.Bool
	templateScannersDone atomic.Bool
	allScansDone         atomic.Bool

	activeStaticWorkers   atomic.Int32
	activeTemplateWorkers atomic.Int32
	activeServiceWorkers  atomic.Int32
)

// startScanProcess kicks off scanning stage in order
func (wr *wranglerRepository) startScanProcess(inScope []string) {
	discoveryDone.Store(false)
	serviceEnumDone.Store(false)
	staticScannersDone.Store(false)
	templateScannersDone.Store(false)
	allScansDone.Store(false)

	activeStaticWorkers.Store(0)
	activeTemplateWorkers.Store(0)
	activeServiceWorkers.Store(0)

	tempDir, err := files.MakeTempDir(project.ProjectBase, project.TempPrefix)
	if err != nil {
		fmt.Printf("unable to create temp scope file directory: %s", err)
	}

	defer func(name string) {
		err = os.RemoveAll(name)
		if err != nil {
			fmt.Printf("unable to delete temp scope file directory: %s", err)
		}
	}(tempDir)

	// Master WaitGroup to track when all processes are done
	var masterWg sync.WaitGroup
	masterWg.Add(4) // Four phases: discovery, static, service enum, template

	// Step 1: Run host discovery
	go func() {
		defer masterWg.Done()
		wr.DiscoveryWorkersInit(inScope, tempDir)
		for !discoveryDone.Load() {
			time.Sleep(time.Second)
		}
		log.Println("[*] Discovery phase completely finished")
	}()

	// Step 2: Start static workers
	go func() {
		defer masterWg.Done()
		wr.staticScanners(wr.staticWorkers.GetAll())
		for activeStaticWorkers.Load() > 0 {
			time.Sleep(time.Second)
		}
		staticScannersDone.Store(true)
		log.Println("[*] Static scanning phase completely finished")
	}()

	// Step 3: Start service enumeration
	go func() {
		defer masterWg.Done()
		wr.serviceEnumeration()
		for !serviceEnumDone.Load() {
			time.Sleep(time.Second)
		}
		log.Println("[*] Service enumeration phase completely finished")
	}()

	// Step 4: Start primary scanners
	go func() {
		defer masterWg.Done()
		wr.templateScanners(wr.templateWorkers.GetAll())
		for activeTemplateWorkers.Load() > 0 {
			time.Sleep(time.Second)
		}
		templateScannersDone.Store(true)
		log.Println("[*] Template scanning phase completely finished")
	}()

	log.Println("[*] Scanning initiated, running in background")

	// Start a monitoring goroutine
	go func() {
		masterWg.Wait()
		log.Println("[*] ALL scanning phases completed")
		allScansDone.Store(true)
		wr.GracefulCloseDown()
	}()
}

// serviceEnumeration scans identified hosts to identify open ports and determine what services are listening
func (wr *wranglerRepository) serviceEnumeration() {
	var wg sync.WaitGroup
	serviceEnumDone.Store(false)
	nmapBin := getBinaryPath(nmap.BinaryName)

	// Add max iterations to prevent infinite loop
	maxIterations := 2000
	iterations := 0

	for {
		if discoveryDone.Load() && wr.serviceEnum.Len() == 0 && activeServiceWorkers.Load() == 0 {
			fmt.Println("[*] Service enumeration completed")
			serviceEnumDone.Store(true)
			return
		}

		if iterations >= maxIterations {
			log.Println("[!] Service enumeration reached maximum iterations - forcing completion")
			serviceEnumDone.Store(true)
			return
		}

		if wr.serviceEnum.Len() == 0 {
			// Gently throttle loops
			time.Sleep(time.Second * 2)
			iterations++
			continue
		}
		iterations = 0 // Reset when targets are processed

		targets := wr.serviceEnum.ReadAndRemoveNFromRegistry(wr.cli.BatchSize)

		// Configure TCP command
		tcpCmd := nmap.NewCommand(nmap.TCP)
		tcpCmd.Add().
			MinHostGroup(100).
			MinRate(150).
			MaxRetries(2).
			AllPorts()

		desc := "TCP service discovery scan"
		wTCP := wr.NewWorkerNoService(nmapBin, nil, nmap.TCP, desc)
		wTCP.Args = tcpCmd.ToArgList()

		// Configure UDP command
		udpCmd := nmap.NewCommand(nmap.UDP)
		udpCmd.Add().
			MinHostGroup(100).
			MinRate(150).
			MaxRetries(2).
			TopPorts(1000)

		desc = "UDP service discovery scan"
		wUDP := wr.NewWorkerNoService(nmapBin, nil, nmap.UDP, desc)
		wUDP.Args = udpCmd.ToArgList()

		workers := []models.Worker{
			wTCP,
			wUDP,
		}

		wg.Add(len(workers))
		activeServiceWorkers.Add(int32(len(workers)))

		log.Println("[*] Starting service enumeration")
		wr.startWorkers(project, workers, targets)
		wr.ServiceEnumerationMonitor(workers)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)

		// Track each worker's completion in a separate goroutine
		for i := range workers {
			w := &workers[i]
			go func(worker *models.Worker) {
				// Wait for worker to complete by monitoring its channels
				select {
				case <-worker.WorkerResponse:
					// Worker has responded, assume it's done
				case <-worker.XMLPathsChan:
					// Worker has produced XML, assume it's done
				case <-time.After(30 * time.Minute):
					log.Printf("[!] Service enum worker %s timed out after 30 minutes", worker.ID)
				}

				wg.Done()
				activeServiceWorkers.Add(-1)
				log.Printf("[*] Service enum worker completed, %d remain active",
					activeServiceWorkers.Load())
			}(w)
		}
	}
}

// staticScanners are defined as scans within the YAML config file which already have ports assigned and do not require modification.
func (wr *wranglerRepository) staticScanners(workers []models.Worker) {
	var count = 0
	for {
		if discoveryDone.Load() && wr.staticTargets.Len() == 0 && activeStaticWorkers.Load() == 0 {
			fmt.Println("[*] Static scanners completed")
			return
		}

		if wr.staticTargets.Len() == 0 {
			// Gently throttle any loops
			time.Sleep(time.Second * 2)
			continue
		}

		log.Printf("[*] Starting %d static scanners", len(workers))
		targets := wr.staticTargets.ReadAndRemoveNFromRegistry(wr.cli.BatchSize)

		// Increment active workers count before starting them
		activeStaticWorkers.Add(int32(len(workers)))

		// Create a WaitGroup for this batch of workers
		var wg sync.WaitGroup
		wg.Add(len(workers))

		wr.startWorkers(project, workers, targets)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)

		log.Printf("[*] Static scanner %d running", count)
		count++

		// Track each worker's completion
		for i := range workers {
			w := &workers[i]
			go func(worker *models.Worker) {
				// Wait for worker to complete by monitoring its channels
				select {
				case <-worker.WorkerResponse:
					// Worker has responded, assume it's done
				case <-worker.XMLPathsChan:
					// Worker has produced XML, assume it's done
				case <-time.After(30 * time.Minute):
					log.Printf("[!] Static scanner worker %s timed out after 30 minutes", worker.ID)
				}

				wg.Done()
				activeStaticWorkers.Add(-1)
				log.Printf("[*] Static scanner worker completed, %d remain active",
					activeStaticWorkers.Load())
			}(w)
		}
	}
}

// TemplateScanners are defined as scans within the YAML config file which do not have ports pre-assigned.
// These scans will be dynamically allocated to target services based on the YAML 'service' field value and aliases
func (wr *wranglerRepository) templateScanners(workers []models.Worker) {
	for {
		if serviceEnumDone.Load() && wr.templateTargets.Len() == 0 &&
			wr.serviceEnum.Len() == 0 && activeTemplateWorkers.Load() == 0 {
			fmt.Println("[*] Template scanners completed")
			return
		}

		if wr.templateTargets.Len() == 0 {
			// Gently throttle any loops
			time.Sleep(time.Second * 2)
			continue
		}

		if len(workers) == 0 {
			log.Println("[!] No template workers, skipping")
			continue
		}

		targets := wr.templateTargets.ReadAndRemoveNFromRegistry(wr.cli.BatchSize)

		// Increment active workers count
		activeTemplateWorkers.Add(int32(len(workers)))

		// Create a WaitGroup for this batch
		var wg sync.WaitGroup
		wg.Add(len(workers))

		log.Printf("[*] Starting %d template scanners", len(workers))
		wr.startWorkers(project, workers, targets)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)
		log.Println("[*] Templated scanners running")

		for i := range workers {
			w := &workers[i]
			go func(worker *models.Worker) {
				// Wait for worker to complete by monitoring its channels
				select {
				case <-worker.WorkerResponse:
					// Worker has responded, assume it's done
				case <-worker.XMLPathsChan:
					// Worker has produced XML, assume it's done
				case <-time.After(30 * time.Minute):
					log.Printf("[!] Template scanner worker %s timed out after 30 minutes", worker.ID)
				}

				wg.Done()
				activeTemplateWorkers.Add(-1)
				log.Printf("[*] Template scanner worker completed, %d remain active",
					activeTemplateWorkers.Load())
			}(w)
		}
	}
}

// AllScansComplete checks if all scans have completed
func (wr *wranglerRepository) AllScansComplete() bool {
	return allScansDone.Load()
}
