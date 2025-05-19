package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/models"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Add these at the package level along with existing atomic booleans
var (
	// Existing
	discoveryDone   atomic.Bool
	serviceEnumDone atomic.Bool

	// New atomic flags to track whether processes have started
	discoveryStarted    atomic.Bool
	serviceEnumStarted  atomic.Bool
	staticScanStarted   atomic.Bool
	templateScanStarted atomic.Bool

	// Add this flag to properly track template scan completion
	templateScanDone atomic.Bool

	// New phase completion WaitGroups
	discoveryWG   sync.WaitGroup
	serviceEnumWG sync.WaitGroup
	staticScanWG  sync.WaitGroup
)

// startScanProcess kicks off scanning stages in order
func (wr *wranglerRepository) startScanProcess() {
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

	// Initialize all process flags to false
	discoveryDone.Store(false)
	serviceEnumDone.Store(false)
	templateScanDone.Store(false) // Initialize the new flag
	discoveryStarted.Store(false)
	serviceEnumStarted.Store(false)
	staticScanStarted.Store(false)
	templateScanStarted.Store(false)

	// Create a WaitGroup to keep the main function alive until all work is done
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
		// The discoveryDone flag should be set in DiscoveryScan by the WaitGroup
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

	// Step 3: Start primary scanners. Depends on serviceEnumeration
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
	var phaseBatchesWG sync.WaitGroup // Track all batches for this phase
	serviceEnumDone.Store(false)

	for {
		// Signal if any targets are available
		if wr.serviceEnum.Len() > 0 && !serviceEnumStarted.Load() {
			log.Println("[*] Service enumeration has started processing targets")
			serviceEnumStarted.Store(true)
		}

		// Exit condition
		if discoveryDone.Load() && wr.serviceEnum.Len() == 0 {
			if serviceEnumStarted.Load() {
				// Wait a bit to ensure no new targets are coming
				time.Sleep(time.Second * 5)

				// Double-check empty queue condition
				if wr.serviceEnum.Len() == 0 {
					// Wait for all in-progress batches to complete before marking phase as done
					log.Println("[*] Waiting for all service enumeration workers to complete...")
					phaseBatchesWG.Wait()
					log.Println("[*] All service enumeration workers completed")
					serviceEnumDone.Store(true)
					break
				}
			} else {
				// If discovery is done but we never started processing targets
				// and queue is empty, we should also exit
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

		// Track this batch in the phase's overall WaitGroup
		phaseBatchesWG.Add(1)
		go func() {
			batchWG.Wait()
			log.Println("[*] Service enumeration batch completed")
			phaseBatchesWG.Done() // Signal this batch is complete
		}()
	}
}

// staticScanners are defined as scans within the YAML config file which already have ports assigned
func (wr *wranglerRepository) staticScanners(workers []models.Worker) {
	var phaseBatchesWG sync.WaitGroup // Track all batches for this phase
	var count = 0

	for {
		// Signal if any targets are available
		if wr.staticTargets.Len() > 0 && !staticScanStarted.Load() {
			log.Println("[*] Static scanners have started processing targets")
			staticScanStarted.Store(true)
		}

		// Exit condition
		if discoveryDone.Load() && wr.staticTargets.Len() == 0 {
			if staticScanStarted.Load() {
				// Wait a bit to ensure no new targets are coming
				time.Sleep(time.Second * 5)

				// Double-check empty queue condition
				if wr.staticTargets.Len() == 0 {
					// Wait for all in-progress batches to complete
					log.Println("[*] Waiting for all static scanners to complete...")
					phaseBatchesWG.Wait()
					log.Println("[*] All static scanners completed")
					break
				}
			} else {
				// If discovery is done but we never started processing targets
				// and queue is empty, we should also exit
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

		var batchWG sync.WaitGroup
		batchWG.Add(len(workers))

		wr.startWorkers(project, workers, targets, &batchWG)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)

		log.Printf("[*] Static scanner batch %d running", count)
		count++

		// Track this batch in the phase's overall WaitGroup
		phaseBatchesWG.Add(1)
		go func() {
			batchWG.Wait()
			log.Println("[*] Static scanner batch completed")
			phaseBatchesWG.Done() // Signal this batch is complete
		}()
	}
}

// templateScanners are defined as scans within the YAML config file which do not have ports pre-assigned
func (wr *wranglerRepository) templateScanners(workers []models.Worker) {
	var phaseBatchesWG sync.WaitGroup // Track all batches for this phase
	templateScanDone.Store(false)     // Initialize to false at start

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
					templateScanDone.Store(true) // Set completion flag
					break
				}
			} else {
				// If service enumeration is done but we never started processing targets
				// and queue is empty, we should also exit
				if wr.templateTargets.Len() == 0 {
					log.Println("[*] Template scanners skipped - no targets")
					templateScanDone.Store(true) // Set completion flag
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
			templateScanDone.Store(true) // Set completion flag if no workers
			break
		}

		targets := wr.templateTargets.ReadAndRemoveNFromRegistry(wr.cli.BatchSize)

		var batchWG sync.WaitGroup
		batchWG.Add(len(workers))

		log.Printf("[*] Starting %d template scanners", len(workers))
		wr.startWorkers(project, workers, targets, &batchWG)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)
		log.Println("[*] Templated scanners batch running")

		// Track this batch in the phase's overall WaitGroup
		phaseBatchesWG.Add(1)
		go func() {
			batchWG.Wait()
			log.Println("[*] Template scanner batch completed")
			phaseBatchesWG.Done() // Signal this batch is complete
		}()
	}
}
