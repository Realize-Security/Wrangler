package wrangler

import (
	"Wrangler/pkg/models"
	"Wrangler/pkg/serializers"
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"reflect"
	"sync"
	"time"
)

func (wr *wranglerRepository) startScanProcess(project *models.Project, inScope []string, exclude string) {
	var discWg *sync.WaitGroup
	var discoveryDone chan struct{}
	if wr.cli.RunDiscovery {
		discWg, discoveryDone = wr.DiscoveryWorkersInit(inScope, exclude)
	} else {
		close(serviceEnum)
		discoveryDone = make(chan struct{})
		close(discoveryDone)
	}

	// Start service enumeration in a goroutine to read serviceEnum immediately
	var parseWg *sync.WaitGroup
	go func() {
		parseWg = wr.ServiceEnumeration(project, discWg, discoveryDone)
	}()

	// Start primary scanners
	primaryWg := wr.PrimaryScanners(project, nil)

	// Wait for discovery to complete if running
	if wr.cli.RunDiscovery {
		discWg.Wait()   // Wait for discovery workers to finish
		<-discoveryDone // Wait for DiscoveryResponseMonitor to close serviceEnum
	}

	// Wait for enumeration and primary scans to complete
	parseWg.Wait()
	close(fullScan)
	primaryWg.Wait()
	log.Println("[startScanProcess] All scanning steps complete.")
}

// DiscoveryScan spawns an Nmap -sn job per host. Returns a WaitGroup.
func (wr *wranglerRepository) DiscoveryScan(workers []models.Worker, exclude string) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		w := &workers[i]
		w.Command = "nmap"
		w.Args = append(w.Args, "-sn")
		if exclude != "" {
			w.Args = append(w.Args, "--excludefile", exclude)
		}

		go func(dw *models.Worker) {
			defer wg.Done()
			dw.Started = time.Now()

			ctx, cancel := context.WithCancel(context.Background())
			dw.CancelFunc = cancel

			cmdObj, outChan, stderrChan, errChan, startErr := runCommandCtx(ctx, dw, dw.Args)
			dw.Cmd = cmdObj

			if startErr != nil {
				log.Printf("Worker %d: Start failed: %v", dw.ID, startErr)
				dw.ErrorChan <- startErr
				dw.WorkerResponse <- ""
				close(dw.WorkerResponse)
				dw.Finished = time.Now()
				cancel()
				return
			}

			go func() {
				stdout := <-outChan
				stderr := <-stderrChan
				err := <-errChan

				log.Printf("Worker %d: Sending %d bytes to WorkerResponse", dw.ID, len(stdout))
				dw.WorkerResponse <- stdout
				if err != nil {
					if stderr != "" {
						fmt.Println(stderr)
						dw.StdError = stderr
					}
					dw.ErrorChan <- err
				} else {
					dw.ErrorChan <- nil
				}
				dw.Finished = time.Now()
				close(dw.WorkerResponse)
				cancel()
			}()

			dw.UserCommand <- "run"
			time.Sleep(5 * time.Second) // Ensure Nmap runs
		}(w)
	}
	return &wg
}

func (wr *wranglerRepository) ServiceEnumeration(project *models.Project, discWg *sync.WaitGroup, discoveryDone <-chan struct{}) *sync.WaitGroup {
	enumDir := path.Join(project.ReportDir, project.Name, "enumeration")
	err := os.MkdirAll(enumDir, 0700)
	if err != nil {
		fmt.Printf("failed to create enum dir: %s", err)
		return nil
	}

	w := models.Worker{
		ID:             1,
		Type:           "nmap",
		Command:        "nmap",
		Description:    "Host service all ports enumeration scans",
		UserCommand:    make(chan string, 1),
		WorkerResponse: make(chan string),
		ErrorChan:      make(chan error),
		XMLPathsChan:   make(chan string),
	}
	w.Args = []string{"-sTV", "-p-"}
	project.Workers = []models.Worker{w}

	// Start enumeration workers immediately, reading from serviceEnum
	log.Println("[ServiceEnumeration] Starting enumeration workers...")
	enumWg := wr.startWorkers(project, serviceEnum, batchSize)
	if enumWg == nil || reflect.ValueOf(*enumWg).FieldByName("state").IsZero() {
		log.Println("[ServiceEnumeration] No targets received from discovery, skipping enumeration")
	} else {
		// Wait for enumeration workers to finish processing
		enumWg.Wait()
		log.Println("[ServiceEnumeration] All enumeration processes ended.")
	}

	// Parse results
	parseWg := wr.MonitorServiceEnum(project.Workers, fullScan)
	wr.SetupSignalHandler(project.Workers, sigCh)
	wr.DrainWorkerErrors(project.Workers, errCh)
	wr.ListenToWorkerErrors(project.Workers, errCh)

	// If discovery is running, wait for it to signal completion in the background
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

// Helper function to signal when serviceEnum is closed
func serviceEnumClosed() <-chan struct{} {
	closed := make(chan struct{})
	go func() {
		for range serviceEnum {
			// Drain the channel until closed
		}
		close(closed)
	}()
	return closed
}

func (wr *wranglerRepository) PrimaryScanners(project *models.Project, enumWg *sync.WaitGroup) *sync.WaitGroup {
	// Load patterns from YAML
	args, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("Unable to load scans: %s", err)
		return nil
	}
	log.Printf("Loaded %d primary scans from YAML", len(args))

	// Build workers for each pattern
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

	// Start them reading from fullScan
	wg := wr.startWorkers(project, fullScan, batchSize)

	// Setup signals & error watchers
	wr.SetupSignalHandler(primaryWorkers, sigCh)
	wr.DrainWorkerErrors(primaryWorkers, errCh)
	wr.ListenToWorkerErrors(primaryWorkers, errCh)

	// We do *not* wait on `enumWg` here, because
	// we want partial concurrency.
	return wg
}
