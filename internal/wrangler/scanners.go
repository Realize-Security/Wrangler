package wrangler

import (
	"Wrangler/pkg/models"
	"Wrangler/pkg/serializers"
	"fmt"
	"log"
	"os"
	"path"
	"reflect"
	"sync"
)

func (wr *wranglerRepository) startScanProcess(project *models.Project, inScope []string, exclude string) {
	var discWg *sync.WaitGroup
	var discoveryDone chan struct{}
	if wr.cli.RunDiscovery {
		log.Println("[startScanProcess] Starting discovery")
		discWg, discoveryDone = wr.DiscoveryWorkersInit(inScope, exclude)
	} else {
		log.Println("[startScanProcess] Skipping discovery")
		close(serviceEnum)
		discoveryDone = make(chan struct{})
		close(discoveryDone)
	}

	log.Println("[startScanProcess] Starting ServiceEnumeration")
	parseWg := wr.ServiceEnumeration(project, discWg, discoveryDone)
	if parseWg == nil {
		log.Println("[startScanProcess] ServiceEnumeration returned nil WaitGroup, exiting")
		return
	}

	log.Println("[startScanProcess] Starting PrimaryScanners")
	primaryWg := wr.PrimaryScanners(project, nil)
	if primaryWg == nil {
		log.Println("[startScanProcess] PrimaryScanners returned nil WaitGroup")
	}

	if wr.cli.RunDiscovery {
		log.Println("[startScanProcess] Waiting for discovery to complete")
		discWg.Wait()
		<-discoveryDone
	}

	log.Println("[startScanProcess] Waiting for enumeration to complete")
	parseWg.Wait()

	log.Println("[startScanProcess] Waiting for primary scans to complete")
	primaryWg.Wait()
	close(fullScan)
	log.Println("[startScanProcess] All scanning steps complete.")
}

func (wr *wranglerRepository) ServiceEnumeration(project *models.Project, discWg *sync.WaitGroup, discoveryDone <-chan struct{}) *sync.WaitGroup {
	enumDir := path.Join(project.ReportDir, project.Name, "enumeration")
	err := os.MkdirAll(enumDir, 0700)
	if err != nil {
		fmt.Printf("failed to create enum dir: %s\n", err)
		return nil
	}

	w := models.Worker{
		ID:             1,
		Type:           "nmap",
		Command:        "nmap",
		Description:    "Host service all ports enumeration scans",
		UserCommand:    make(chan string, 1),
		WorkerResponse: nil,
		ErrorChan:      make(chan error),
		XMLPathsChan:   make(chan string),
	}
	w.Args = []string{"-sT", "-p 80,443"}
	project.Workers = []models.Worker{w}

	log.Println("[ServiceEnumeration] Starting enumeration workers...")
	enumWg := wr.startWorkers(project, serviceEnum, batchSize)

	// Wait for discovery to complete before checking targets
	if discWg != nil {
		log.Println("[ServiceEnumeration] Waiting for discovery to complete")
		discWg.Wait()
		<-discoveryDone
	}

	// Check if there are any active workers after discovery
	if enumWg == nil || reflect.ValueOf(*enumWg).FieldByName("state").IsZero() {
		log.Println("[ServiceEnumeration] No targets received from discovery, skipping enumeration")
		var wg sync.WaitGroup
		return &wg
	}

	// Start MonitorServiceEnum concurrently
	parseWg := wr.MonitorServiceEnum(project.Workers, fullScan)

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
	args, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("Unable to load scans: %s", err)
		return nil
	}
	if len(args) == 0 {
		log.Println("[PrimaryScanners] No scan patterns in YAML, skipping")
		var wg sync.WaitGroup
		go func() {
			for t := range fullScan {
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
			Args:           pattern.Args,
			Description:    pattern.Description,
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string),
			ErrorChan:      make(chan error),
			XMLPathsChan:   make(chan string),
		}
		primaryWorkers = append(primaryWorkers, w)
	}

	project.Workers = primaryWorkers
	log.Printf("[PrimaryScanners] Initialized %d workers", len(primaryWorkers))
	wg := wr.startWorkers(project, fullScan, batchSize)
	if wg == nil {
		log.Println("[PrimaryScanners] startWorkers returned nil")
		var emptyWg sync.WaitGroup
		return &emptyWg
	}

	wr.SetupSignalHandler(primaryWorkers, sigCh)
	wr.DrainWorkerErrors(primaryWorkers, errCh)
	wr.ListenToWorkerErrors(primaryWorkers, errCh)
	log.Println("[PrimaryScanners] Primary scanners running")
	return wg
}
