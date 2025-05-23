package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/models"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Add these at the package level along with existing atomic booleans
var (
	discoveryDone   atomic.Bool
	serviceEnumDone atomic.Bool

	// Atomic flags to track whether processes have started
	discoveryStarted    atomic.Bool
	serviceEnumStarted  atomic.Bool
	staticScanStarted   atomic.Bool
	templateScanStarted atomic.Bool

	// Track template scan completion
	templateScanDone atomic.Bool

	// Phase completion WaitGroups
	discoveryWG   sync.WaitGroup
	serviceEnumWG sync.WaitGroup
	staticScanWG  sync.WaitGroup
)

// startScanProcess kicks off scanning stages in order
func (wr *wranglerRepository) startScanProcess() {
	tempDir, err := files.MakeTempDir(project.ProjectBase, project.TempPrefix)
	if err != nil {
		log.Printf("unable to create temp scope file directory: %s", err)
	}

	defer func(name string) {
		err = os.RemoveAll(name)
		if err != nil {
			log.Printf("unable to delete temp scope file directory: %s", err)
		}
	}(tempDir)

	// Initialize all process flags to false
	discoveryDone.Store(false)
	serviceEnumDone.Store(false)
	templateScanDone.Store(false)
	discoveryStarted.Store(false)
	serviceEnumStarted.Store(false)
	staticScanStarted.Store(false)
	templateScanStarted.Store(false)

	// WaitGroup to keep the main function alive until all work is done
	var mainWg sync.WaitGroup

	// Step 1: Run host discovery
	discoveryWG.Add(1)
	mainWg.Add(1)
	log.Println("[*] Starting host discovery phase")
	go func() {
		defer discoveryWG.Done()
		defer mainWg.Done()
		wr.DiscoveryWorkersInit(wr.hostDiscoveryWorkers.GetAll(), project.InScopeHosts, tempDir)
		log.Println("[*] Discovery workers initialization completed")
	}()

	// Step 2a: Start static workers. Depends on DiscoveryWorkersInit
	staticScanWG.Add(1)
	mainWg.Add(1)
	go func() {
		defer staticScanWG.Done()
		defer mainWg.Done()
		log.Println("[*] Waiting for discovery to start before static scanners")
		for !discoveryStarted.Load() {
			time.Sleep(time.Second)
		}
		log.Println("[*] Starting static scanners phase")
		wr.staticScanners(wr.staticWorkers.GetAll())
		log.Println("[*] Static scanners phase completed")
	}()

	// Step 2b: Start service enumeration. Depends on DiscoveryWorkersInit
	serviceEnumWG.Add(1)
	mainWg.Add(1)
	go func() {
		defer serviceEnumWG.Done()
		defer mainWg.Done()
		log.Println("[*] Waiting for discovery to start before service enum")
		for !discoveryStarted.Load() {
			time.Sleep(time.Second)
		}
		log.Println("[*] Starting service enumeration phase")
		wr.serviceEnumeration(wr.serviceDiscoveryWorkers.GetAll())
		log.Println("[*] Service enumeration phase completed")
	}()

	// Step 3: Start template scanners. Depends on serviceEnumeration
	mainWg.Add(1)
	go func() {
		defer mainWg.Done()
		log.Println("[*] Waiting for service enum to start before templates")
		for !serviceEnumStarted.Load() {
			time.Sleep(time.Second)
		}
		log.Println("[*] Starting template scanners phase")
		wr.templateScanners(wr.templateWorkers.GetAll())
		log.Println("[*] Template scanners phase completed")
	}()

	// Wait for all goroutines to finish their work
	log.Println("[*] Waiting for all scan phases to complete")
	mainWg.Wait()
	log.Println("[*] All scan phases completed")

	log.Printf("[*] Project '%s' completed execution with ID: '%s'", wr.cli.ProjectName, project.ExecutionID.String())
	logProjectDetails(project)
}

// serviceEnumeration scans identified hosts to identify open ports and determine what services are listening
func (wr *wranglerRepository) serviceEnumeration(templates []models.Worker) {
	var phaseBatchesWG sync.WaitGroup
	serviceEnumDone.Store(false)

	for {
		if wr.serviceEnum.Len() > 0 && !serviceEnumStarted.Load() {
			log.Println("[*] Service enumeration has started processing targets")
			serviceEnumStarted.Store(true)
		}

		if discoveryDone.Load() && wr.serviceEnum.Len() == 0 {
			if serviceEnumStarted.Load() {
				time.Sleep(time.Second * 5)

				if wr.serviceEnum.Len() == 0 {
					log.Println("[*] Waiting for all service enumeration workers to complete...")
					phaseBatchesWG.Wait()
					log.Println("[*] All service enumeration workers completed")
					serviceEnumDone.Store(true)
					break
				}
			} else {
				if wr.serviceEnum.Len() == 0 {
					log.Println("[*] Service enumeration skipped - no targets")
					serviceEnumDone.Store(true)
					break
				}
				time.Sleep(time.Second * 2)
			}
		}

		if wr.serviceEnum.Len() == 0 {
			time.Sleep(time.Second * 2)
			continue
		}

		workers := make([]models.Worker, 0)
		targets := wr.serviceEnum.ReadAndRemoveNFromRegistry(wr.cli.BatchSize)

		for _, tw := range templates {
			w := wr.DuplicateWorker(&tw)
			workers = append(workers, w)
		}

		var batchWG sync.WaitGroup
		batchWG.Add(len(workers))

		log.Printf("[*] Starting service enumeration batch with %d workers", len(workers))
		wr.startWorkers(project, workers, targets, &batchWG)
		wr.MonitorServiceEnum(workers)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)

		phaseBatchesWG.Add(1)
		go func() {
			batchWG.Wait()
			log.Println("[*] Service enumeration batch completed")
			phaseBatchesWG.Done()
		}()
	}
}

// staticScanners are defined as scans within the YAML config file which already have ports assigned
func (wr *wranglerRepository) staticScanners(workers []models.Worker) {
	var phaseBatchesWG sync.WaitGroup
	var count = 0

	for {
		if wr.staticTargets.Len() > 0 && !staticScanStarted.Load() {
			log.Println("[*] Static scanners have started processing targets")
			staticScanStarted.Store(true)
		}

		// Exit condition
		if discoveryDone.Load() && wr.staticTargets.Len() == 0 {
			if staticScanStarted.Load() {
				time.Sleep(time.Second * 5)

				if wr.staticTargets.Len() == 0 {
					log.Println("[*] Waiting for all static scanners to complete...")
					phaseBatchesWG.Wait()
					log.Println("[*] All static scanners completed")
					break
				}
			} else {
				if wr.staticTargets.Len() == 0 {
					log.Println("[*] Static scanners skipped - no targets")
					break
				}
				time.Sleep(time.Second * 2)
			}
		}

		if wr.staticTargets.Len() == 0 {
			time.Sleep(time.Second * 2)
			continue
		}

		log.Printf("[*] Starting %d static scanners", len(workers))
		targets := wr.staticTargets.ReadAndRemoveNFromRegistry(wr.cli.BatchSize)

		batchWorkers := make([]models.Worker, 0)
		for _, tw := range workers {
			w := wr.DuplicateWorker(&tw)
			batchWorkers = append(batchWorkers, w)
		}

		var batchWG sync.WaitGroup
		batchWG.Add(len(batchWorkers))

		wr.startWorkers(project, batchWorkers, targets, &batchWG)
		wr.SetupSignalHandler(batchWorkers, sigCh)
		wr.DrainWorkerErrors(batchWorkers, errCh)
		wr.ListenToWorkerErrors(batchWorkers, errCh)

		log.Printf("[*] Static scanner batch %d running", count)
		count++

		phaseBatchesWG.Add(1)
		go func() {
			batchWG.Wait()
			log.Println("[*] Static scanner batch completed")
			phaseBatchesWG.Done()
		}()
	}
}

// templateScanners are defined as scans within the YAML config file which do not have ports pre-assigned
func (wr *wranglerRepository) templateScanners(workers []models.Worker) {
	var phaseBatchesWG sync.WaitGroup
	templateScanDone.Store(false)

	for {
		// Signal if any targets are available
		if wr.templateTargets.Len() > 0 && !templateScanStarted.Load() {
			log.Println("[*] Template scanners have started processing targets")
			templateScanStarted.Store(true)
		}

		// Exit condition
		if serviceEnumDone.Load() && wr.templateTargets.Len() == 0 {
			if templateScanStarted.Load() {
				// Wait a bit to ensure no new targets are coming
				time.Sleep(time.Second * 5)

				// Double-check empty queue condition
				if wr.templateTargets.Len() == 0 {
					// Wait for all in-progress batches to complete
					log.Println("[*] Waiting for all template scanners to complete...")
					phaseBatchesWG.Wait()
					log.Println("[*] All template scanners completed")
					templateScanDone.Store(true)
					break
				}
			} else {
				if wr.templateTargets.Len() == 0 {
					log.Println("[*] Template scanners skipped - no targets")
					templateScanDone.Store(true)
					break
				}
				time.Sleep(time.Second * 2)
			}
		}

		if wr.templateTargets.Len() == 0 {
			time.Sleep(time.Second * 2)
			continue
		}

		if len(workers) == 0 {
			log.Println("[!] No template workers, skipping")
			templateScanDone.Store(true)
			break
		}

		targets := wr.templateTargets.ReadAndRemoveNFromRegistry(wr.cli.BatchSize)

		batchWorkers := make([]models.Worker, 0)
		for _, tw := range workers {
			w := wr.DuplicateWorker(&tw)
			batchWorkers = append(batchWorkers, w)
		}

		var batchWG sync.WaitGroup
		batchWG.Add(len(batchWorkers))

		log.Printf("[*] Starting %d template scanners", len(batchWorkers))
		wr.startWorkers(project, batchWorkers, targets, &batchWG)
		wr.SetupSignalHandler(batchWorkers, sigCh)
		wr.DrainWorkerErrors(batchWorkers, errCh)
		wr.ListenToWorkerErrors(batchWorkers, errCh)
		log.Println("[*] Templated scanners batch running")

		phaseBatchesWG.Add(1)
		go func() {
			batchWG.Wait()
			log.Println("[*] Template scanner batch completed")
			phaseBatchesWG.Done()
		}()
	}
}
