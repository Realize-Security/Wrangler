package wrangler

import (
	"Wrangler/pkg/models"
	"Wrangler/pkg/serializers"
	"fmt"
	"log"
	"os"
	"path"
	"sync"
	"time"
)

func (wr *wranglerRepository) startScanProcess(project *models.Project, inScope []string, exclude string) {
	var discWg *sync.WaitGroup
	var discoveryDone chan struct{}
	if wr.cli.RunDiscovery {
		log.Println("[startScanProcess] Starting discovery")
		discWg, discoveryDone = wr.DiscoveryWorkersInit(inScope, exclude)
	} else {
		log.Println("[startScanProcess] Skipping discovery")
		close(wr.serviceEnum)
		discoveryDone = make(chan struct{})
		close(discoveryDone)
	}

	var primaryWg *sync.WaitGroup
	go func() {
		log.Println("[startScanProcess] Launching PrimaryScanners goroutine")
		log.Println("[startScanProcess] Starting PrimaryScanners")
		primaryWg = wr.PrimaryScanners(project, nil)
		if primaryWg == nil {
			log.Println("[startScanProcess] PrimaryScanners returned nil WaitGroup")
		}
		log.Println("[startScanProcess] PrimaryScanners goroutine completed")
	}()

	time.Sleep(100 * time.Millisecond) // Ensure goroutine starts

	log.Println("[startScanProcess] Starting ServiceEnumeration")
	parseWg := wr.ServiceEnumeration(project, discWg, discoveryDone)
	if parseWg == nil {
		log.Println("[startScanProcess] ServiceEnumeration returned nil WaitGroup, exiting")
		return
	}

	if wr.cli.RunDiscovery {
		log.Println("[startScanProcess] Waiting for discovery to complete")
		discWg.Wait()
		<-discoveryDone
	}

	log.Println("[startScanProcess] Waiting for enumeration to complete")
	parseWg.Wait()

	log.Println("[startScanProcess] Waiting for primary scans to complete")
	if primaryWg != nil {
		primaryWg.Wait()
		log.Println("[startScanProcess] Primary scans WaitGroup completed")
	} else {
		log.Println("[startScanProcess] PrimaryWg was nil")
	}

	close(wr.fullScan)
	log.Println("[startScanProcess] Closed fullScan channel")
	log.Println("[startScanProcess] All scanning steps complete")
}

func (wr *wranglerRepository) ServiceEnumeration(project *models.Project, discWg *sync.WaitGroup, discoveryDone <-chan struct{}) *sync.WaitGroup {
	enumDir := path.Join(project.ReportDirParent, project.Name, "enumeration")
	err := os.MkdirAll(enumDir, 0700)
	if err != nil {
		fmt.Printf("failed to create enum dir: %s\n", err)
		return nil
	}

	// Load scan patterns from YAML
	args, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil || len(args) == 0 {
		log.Printf("[ServiceEnumeration] Failed to load YAML or no scans: %v", err)
		return nil
	}
	log.Printf("[ServiceEnumeration] Loaded %d scan patterns from YAML", len(args))

	// Use the first YAML pattern for enumeration (assuming one scan for simplicity)
	w := models.Worker{
		ID:             1,
		Type:           args[0].Tool,
		Command:        args[0].Tool,
		Description:    args[0].Description,
		UserCommand:    make(chan string, 1),
		WorkerResponse: nil,
		ErrorChan:      make(chan error),
		XMLPathsChan:   make(chan string),
	}
	w.Args = args[0].Args // e.g., ["-sV", "-p 3389", "-T4", "-v"]
	project.Workers = []models.Worker{w}

	log.Println("[ServiceEnumeration] Starting enumeration workers...")
	enumWg := wr.startWorkers(project, wr.serviceEnum, batchSize)

	if discWg != nil {
		log.Println("[ServiceEnumeration] Waiting for discovery to complete")
		discWg.Wait()
		<-discoveryDone
	}

	parseWg := wr.MonitorServiceEnum(project.Workers, wr.fullScan)
	enumWg.Wait()
	log.Println("[ServiceEnumeration] All enumeration processes ended.")

	wr.SetupSignalHandler(project.Workers, sigCh)
	wr.DrainWorkerErrors(project.Workers, errCh)
	wr.ListenToWorkerErrors(project.Workers, errCh)

	if discWg != nil {
		go func() {
			discWg.Wait()
			<-discoveryDone
			log.Println("[ServiceEnumeration] Discovery fully completed.")
		}()
	}

	log.Println("[ServiceEnumeration] Returning parseWg")
	return parseWg
}

func (wr *wranglerRepository) PrimaryScanners(project *models.Project, enumWg *sync.WaitGroup) *sync.WaitGroup {
	log.Println("[PrimaryScanners] Entered function")
	args, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("[PrimaryScanners] Unable to load scans: %s", err)
		return nil
	}
	if len(args) == 0 {
		log.Println("[PrimaryScanners] No scan patterns in YAML, skipping")
		var wg sync.WaitGroup
		go func() {
			for t := range wr.fullScan {
				log.Printf("[PrimaryScanners] Draining target %s with ports %v", t.Host, t.Ports)
			}
		}()
		return &wg
	}
	log.Printf("[PrimaryScanners] Loaded %d primary scans from YAML", len(args))

	var primaryWorkers []models.Worker
	for i, pattern := range args {
		w := models.Worker{
			ID:             i,
			Type:           pattern.Tool,
			Command:        pattern.Tool,
			Args:           pattern.Args, // e.g., ["-sV", "-p 3389", "-T4", "-v"]
			Description:    pattern.Description,
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string, 1),
			ErrorChan:      make(chan error, 1),
			XMLPathsChan:   make(chan string, 1),
		}
		primaryWorkers = append(primaryWorkers, w)
	}

	project.Workers = primaryWorkers
	log.Printf("[PrimaryScanners] Initialized %d workers", len(primaryWorkers))

	wg := wr.startWorkers(project, wr.fullScan, batchSize)
	if wg == nil {
		log.Println("[PrimaryScanners] startWorkers returned nil")
		var emptyWg sync.WaitGroup
		return &emptyWg
	}

	go func() {
		defer log.Println("[PrimaryScanners] Response monitor goroutine exited")
		completed := 0
		for completed < len(primaryWorkers) {
			for _, w := range primaryWorkers {
				select {
				case resp, ok := <-w.WorkerResponse:
					if ok {
						log.Printf("[PrimaryScanners] Worker %d response: %d bytes", w.ID, len(resp))
						completed++
					}
				case err, ok := <-w.ErrorChan:
					if ok {
						if err != nil {
							log.Printf("[PrimaryScanners] Worker %d error: %v", w.ID, err)
						} else {
							log.Printf("[PrimaryScanners] Worker %d completed successfully", w.ID)
						}
						completed++
					}
				case <-time.After(60 * time.Second):
					log.Printf("[PrimaryScanners] Timeout waiting for remaining workers (%d/%d completed)", completed, len(primaryWorkers))
					return
				}
			}
		}
	}()

	wr.SetupSignalHandler(primaryWorkers, sigCh)
	wr.DrainWorkerErrors(primaryWorkers, errCh)
	wr.ListenToWorkerErrors(primaryWorkers, errCh)
	log.Println("[PrimaryScanners] Primary scanners running")
	return wg
}
