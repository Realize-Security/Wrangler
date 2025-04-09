package wrangler

import (
	"Wrangler/pkg/models"
	"Wrangler/pkg/serializers"
	"fmt"
	"log"
	"os"
	"path"
	"sync"
)

func (wr *wranglerRepository) startScanProcess(
	project *models.Project,
	inScope []string,
	exclude string,
) {
	var discWg *sync.WaitGroup
	var discoveryDone chan struct{}

	// ---- 1) Discovery  ----
	if wr.cli.RunDiscovery {
		log.Println("[startScanProcess] Starting discovery")
		discWg, discoveryDone = wr.DiscoveryWorkersInit(inScope, exclude)
	} else {
		log.Println("[startScanProcess] Skipping discovery")
		close(wr.serviceEnum)
		discoveryDone = make(chan struct{})
		close(discoveryDone)
	}

	// Wait for discovery to finish if it ran
	if wr.cli.RunDiscovery {
		log.Println("[startScanProcess] Waiting for discovery to complete")
		log.Println("[DEBUG] about to discWg.Wait()")
		discWg.Wait()
		log.Println("[DEBUG] discWg.Wait() returned")
		<-discoveryDone
	}

	log.Println("[startScanProcess] Starting ServiceEnumeration")
	parseWg := wr.ServiceEnumeration(project)

	log.Println("[startScanProcess] Waiting for enumeration to complete")
	log.Println("[DEBUG] about to parseWg.Wait()")
	parseWg.Wait()
	log.Println("[DEBUG] parseWg.Wait() returned")

	close(wr.fullScan)
	log.Println("[startScanProcess] Closed fullScan channel")

	log.Println("[startScanProcess] Starting PrimaryScanners")
	primaryWg := wr.PrimaryScanners(project)
	if primaryWg != nil {
		log.Println("[DEBUG] about to primaryWg.Wait()")
		primaryWg.Wait()
		log.Println("[DEBUG] primaryWg.Wait() returned")
	}

	log.Println("[startScanProcess] All scanning steps complete")
	// optional: wr.CleanupPermissions(...)
	log.Println("[startScanProcess] Application shutting down gracefully")
}

func (wr *wranglerRepository) ServiceEnumeration(project *models.Project) *sync.WaitGroup {
	enumDir := path.Join(project.ReportDirParent, project.Name, "enumeration")
	err := os.MkdirAll(enumDir, 0700)
	if err != nil {
		fmt.Printf("failed to create enum dir: %s\n", err)
		return nil
	}

	// Use the first YAML pattern for enumeration (assuming one scan for simplicity)
	w := models.Worker{
		ID:             1,
		Type:           "nmap",
		Command:        "nmap",
		Description:    "service discovery scan",
		UserCommand:    make(chan string, 1),
		WorkerResponse: nil,
		ErrorChan:      make(chan error),
		XMLPathsChan:   make(chan string),
	}
	w.Args = []string{"-sT", "-p 443"}
	workers := []models.Worker{w}

	log.Println("[ServiceEnumeration] Starting enumeration workers...")
	enumWg := wr.startWorkers(project, workers, wr.serviceEnum, batchSize)

	//if discWg != nil {
	//	log.Println("[ServiceEnumeration] Waiting for discovery to complete")
	//	discWg.Wait()
	//	log.Println("[ServiceEnumeration] Waiting completed")
	//	<-discoveryDone
	//}

	parseWg := wr.MonitorServiceEnum(workers, wr.fullScan)
	enumWg.Wait()
	log.Println("[ServiceEnumeration] All enumeration processes ended.")

	wr.SetupSignalHandler(workers, sigCh)
	wr.DrainWorkerErrors(workers, errCh)
	wr.ListenToWorkerErrors(workers, errCh)

	//if discWg != nil {
	//	go func() {
	//		discWg.Wait()
	//		<-discoveryDone
	//		log.Println("[ServiceEnumeration] Discovery fully completed.")
	//	}()
	//}

	log.Println("[ServiceEnumeration] Returning parseWg")
	return parseWg
}
func (wr *wranglerRepository) PrimaryScanners(project *models.Project) *sync.WaitGroup {
	log.Println("[PrimaryScanners] Entered function")

	// Load scan definitions from YAML
	args, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("[PrimaryScanners] Unable to load scans: %s", err)
		return nil
	}

	if len(args) == 0 {
		log.Println("[PrimaryScanners] No scan patterns in YAML, skipping")
		// If nothing to do, just drain the 'wr.fullScan' channel
		// so we don't block the pipeline.
		var wg sync.WaitGroup
		go func() {
			for t := range wr.fullScan {
				log.Printf("[PrimaryScanners] Draining target %s with ports %v", t.Host, t.Ports)
			}
		}()
		return &wg
	}

	log.Printf("[PrimaryScanners] Loaded %d primary scans from YAML", len(args))

	// Build out a slice of "potential" worker definitions.
	var workers []models.Worker
	for i, pattern := range args {
		w := models.Worker{
			ID:          i,
			Type:        pattern.Tool,
			Command:     pattern.Tool,
			Args:        pattern.Args, // e.g., ["-sS", "-p 3389", "-T4"]
			Description: pattern.Description,

			// Channels for control & data
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string, 1),
			ErrorChan:      make(chan error, 1),
			XMLPathsChan:   make(chan string, 1),
		}
		workers = append(workers, w)
	}

	// Attach these workers to the project so we can manage them.
	log.Printf("[PrimaryScanners] Initialized %d workers", len(workers))

	// Now start the workers. They read targets from 'wr.fullScan'.
	// If 'wr.fullScan' has no open ports, no actual scans are spawned,
	// and the returned WaitGroup completes quickly.
	wg := wr.startWorkers(project, workers, wr.fullScan, batchSize)
	if wg == nil {
		log.Println("[PrimaryScanners] startWorkers returned nil")
		var emptyWg sync.WaitGroup
		return &emptyWg
	}

	// Setup signal & error handling for these workers
	wr.SetupSignalHandler(workers, sigCh)
	wr.DrainWorkerErrors(workers, errCh)
	wr.ListenToWorkerErrors(workers, errCh)

	// We rely on the WaitGroup (wg) to know when workers have all finished,
	// instead of spinning up our own "monitor" goroutine that might block forever.
	log.Println("[PrimaryScanners] Primary scanners running")
	return wg
}
