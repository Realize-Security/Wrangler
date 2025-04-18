package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/models"
	"Wrangler/pkg/serializers"
	"fmt"
	"log"
	"os"
	"sync"
)

func (wr *wranglerRepository) startScanProcess(
	project *models.Project,
	inScope []string,
	exclude string,
) {
	var discWg *sync.WaitGroup
	var discoveryDone chan struct{}

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

	if wr.cli.RunDiscovery {
		log.Println("[*] Starting discovery")
		discWg, discoveryDone = wr.DiscoveryWorkersInit(inScope, exclude, tempDir, project)
	} else {
		log.Println("[*] Skipping discovery")
		close(wr.serviceEnum)
		discoveryDone = make(chan struct{})
		close(discoveryDone)
	}

	if wr.cli.RunDiscovery {
		log.Println("[*] Waiting for discovery to complete")
		discWg.Wait()
		log.Println("[DEBUG] discWg.Wait() returned")
		<-discoveryDone
	}

	log.Println("[*] Starting ServiceEnumeration")
	parseWg := wr.ServiceEnumeration(project)

	log.Println("[*] Waiting for enumeration to complete")
	parseWg.Wait()
	log.Println("[DEBUG] parseWg.Wait() returned")

	close(wr.fullScan)

	log.Println("[*] Starting PrimaryScanners")
	primaryWg := wr.PrimaryScanners(project)
	if primaryWg != nil {
		primaryWg.Wait()
		log.Println("[DEBUG] primaryWg.Wait() returned")
	}

	log.Println("[*] All scanning steps complete. Shutting down.")
}

func (wr *wranglerRepository) ServiceEnumeration(project *models.Project) *sync.WaitGroup {
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
	// TODO: Make this more comprehensive. Ok for now for debugging and dev
	w.Args = []string{"-sT", "-p", "443"}
	workers := []models.Worker{w}

	log.Println("[*] Starting enumeration workers...")
	enumWg := wr.startWorkers(project, workers, wr.serviceEnum, batchSize)

	parseWg := wr.MonitorServiceEnum(workers, wr.fullScan)

	wr.SetupSignalHandler(workers, sigCh)
	wr.DrainWorkerErrors(workers, errCh)
	wr.ListenToWorkerErrors(workers, errCh)

	enumWg.Wait()
	log.Println("[*] All enumeration processes ended.")
	return parseWg
}
func (wr *wranglerRepository) PrimaryScanners(project *models.Project) *sync.WaitGroup {
	log.Println("[*] Starting primary scanners")

	args, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("[!] Unable to load scans: %s", err)
		return nil
	}

	if len(args) == 0 {
		log.Println("[!] No scan patterns in YAML, skipping")
		var wg sync.WaitGroup
		go func() {
			for t := range wr.fullScan {
				log.Printf("[*] Draining target %s with ports %v", t.Host, t.Ports)
			}
		}()
		return &wg
	}

	log.Printf("[*] Loaded %d primary scans from YAML", len(args))

	var workers []models.Worker
	for i, pattern := range args {
		w := models.Worker{
			ID:          i,
			Type:        pattern.Tool,
			Command:     pattern.Tool,
			Args:        pattern.Args,
			Description: pattern.Description,

			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string, 1),
			ErrorChan:      make(chan error, 1),
			XMLPathsChan:   make(chan string, 1),
		}
		workers = append(workers, w)
	}

	log.Printf("[*] Initialized %d workers", len(workers))

	wg := wr.startWorkers(project, workers, wr.fullScan, batchSize)
	if wg == nil {
		log.Println("[!] No workers returned for primary scanners")
		var emptyWg sync.WaitGroup
		return &emptyWg
	}

	wr.SetupSignalHandler(workers, sigCh)
	wr.DrainWorkerErrors(workers, errCh)
	wr.ListenToWorkerErrors(workers, errCh)

	log.Println("[*] Primary scanners running")
	return wg
}
