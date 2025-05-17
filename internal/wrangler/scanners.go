package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/internal/nmap"
	"Wrangler/pkg/models"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// startScanProcess kicks off scanning stage in order
func (wr *wranglerRepository) startScanProcess(inScope []string) {
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

	// Step 1: Run host discovery
	wr.DiscoveryWorkersInit(inScope, tempDir)

	// Step 2: Start static workers
	wr.staticScanners(wr.staticWorkers.GetAll())

	// Step 3: Start  service enumeration
	wr.serviceEnumeration()

	// Step 4: Start primary scanners
	wr.templateScanners(wr.templateWorkers.GetAll())

	log.Printf("[*] Project '%s' completed Execution ID: '%s'", wr.cli.ProjectName, project.ExecutionID.String())
	logProjectDetails(project)
}

// serviceEnumeration scans identified hosts to identify open ports and determine what services are listening
func (wr *wranglerRepository) serviceEnumeration() {
	var wg sync.WaitGroup
	serviceEnumDone.Store(false)
	nmapBin := getBinaryPath(nmap.BinaryName)

	discoveryCompleted := false
	emptyQueueCounter := 0 // To avoid exiting too early due to temporary empty queue

	for {
		// Update our tracking of discovery completion status
		if !discoveryCompleted && discoveryDone.Load() {
			discoveryCompleted = true
			log.Println("[*] Host discovery phase completed, continuing service enumeration")
		}

		// Check if it's time to exit the loop
		if discoveryCompleted && wr.serviceEnum.Len() == 0 {
			// Wait a bit longer to ensure no new items are added
			emptyQueueCounter++

			// Exit only if queue remains empty for multiple checks
			// This handles the case where targets might be added to the queue after we checked
			if emptyQueueCounter >= 5 { // Adjust this value as needed
				fmt.Println("[*] Service enumeration completed")
				serviceEnumDone.Store(true)
				return
			}

			// Sleep before checking again to allow time for queue to be populated
			time.Sleep(time.Second * 2)
			continue
		}

		// Reset counter if we found items
		if wr.serviceEnum.Len() > 0 {
			emptyQueueCounter = 0
		}

		if wr.serviceEnum.Len() == 0 {
			// Gently throttle loops
			time.Sleep(time.Second * 2)
			continue
		}

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

		log.Println("[*] Starting service enumeration")
		wr.startWorkers(project, workers, targets, &wg)
		wr.MonitorServiceEnum(workers)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)

		go func() {
			wg.Wait()
			log.Println("[*] Worker batch completed")
		}()
	}
}

// staticScanners are defined as scans within the YAML config file which already have ports assigned and do not require modification.
func (wr *wranglerRepository) staticScanners(workers []models.Worker) {
	var wg sync.WaitGroup
	var count = 0
	discoveryCompleted := false
	emptyQueueCounter := 0
	allBatchesComplete := true

	for {
		if !discoveryCompleted && discoveryDone.Load() {
			discoveryCompleted = true
			log.Println("[*] Host discovery phase completed, continuing static scanners")
		}

		// Exit condition - only if queue is empty for multiple checks AND all batches are complete
		if discoveryCompleted && wr.staticTargets.Len() == 0 {
			emptyQueueCounter++

			if emptyQueueCounter >= 5 && allBatchesComplete {
				fmt.Println("[*] Static scanners completed")
				break
			}

			time.Sleep(time.Second * 2)
			continue
		}

		// Reset counter
		if wr.staticTargets.Len() > 0 {
			emptyQueueCounter = 0
		}

		if wr.staticTargets.Len() == 0 {
			// Gently throttle any loops
			time.Sleep(time.Second * 2)
			continue
		}

		log.Printf("[*] Starting %d static scanners", len(workers))
		targets := wr.staticTargets.ReadAndRemoveNFromRegistry(wr.cli.BatchSize)

		allBatchesComplete = false

		wg.Add(len(workers))
		wr.startWorkers(project, workers, targets, &wg)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)

		log.Printf("[*] Static scanner %d running", count)
		count++

		go func() {
			wg.Wait()
			log.Println("[*] Static scanner batch completed")
			// Only set the flag if no more batches are being processed
			// This avoids a race condition where a new batch starts just as an old one finishes
			if wr.staticTargets.Len() == 0 {
				allBatchesComplete = true
			}
		}()
	}
}

// TemplateScanners are defined as scans within the YAML config file which do not have ports pre-assigned.
// These scans will be dynamically allocated to target services based on the YAML 'service' field value and aliases
func (wr *wranglerRepository) templateScanners(workers []models.Worker) {
	var wg sync.WaitGroup
	serviceEnumCompleted := false
	emptyQueueCounter := 0
	allBatchesComplete := true // Start true, set to false when a batch starts, set back to true when all complete

	for {
		if !serviceEnumCompleted && serviceEnumDone.Load() {
			serviceEnumCompleted = true
			log.Println("[*] Service enumeration phase completed, continuing template scanners")
		}

		// Exit condition - only if queue is empty for multiple checks AND all batches are complete
		if discoveryDone.Load() && serviceEnumCompleted && wr.templateTargets.Len() == 0 && wr.serviceEnum.Len() == 0 {
			emptyQueueCounter++

			if emptyQueueCounter >= 5 && allBatchesComplete {
				fmt.Println("[*] Template scanners completed")
				break
			}

			time.Sleep(time.Second * 2)
			continue
		}

		// Reset counter
		if wr.templateTargets.Len() > 0 || wr.serviceEnum.Len() > 0 {
			emptyQueueCounter = 0
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

		// Mark that a batch is starting
		allBatchesComplete = false

		log.Printf("[*] Starting %d template scanners", len(workers))
		wg.Add(len(workers))
		wr.startWorkers(project, workers, targets, &wg)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)
		log.Println("[*] Templated scanners running")

		// Start a goroutine to wait for this batch to complete
		go func() {
			wg.Wait()
			log.Println("[*] Template scanner batch completed")
			// Only set the flag if no more batches are being processed
			// This avoids a race condition where a new batch starts just as an old one finishes
			if wr.templateTargets.Len() == 0 && wr.serviceEnum.Len() == 0 {
				allBatchesComplete = true
			}
		}()
	}
}
