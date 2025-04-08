package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/models"
	"Wrangler/pkg/serializers"
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"sync"
	"time"
)

func (wr *wranglerRepository) startScanProcess(project *models.Project, inScope []string, exclude string) {
	var discWg *sync.WaitGroup
	var err error
	if wr.cli.RunDiscovery {
		discWg = wr.DiscoveryWorkersInit(inScope, exclude)
	} else {
		inScopeFile, err = files.WriteSliceToFile(scopeDir, inScopeFile, inScope)
		if err != nil {
			fmt.Printf("Failed to write in-scope file: %v\n", err)
			return
		}
		close(serviceEnum)
	}

	enumWg := wr.ServiceEnumeration(project, discWg)
	//enumWg.Wait()
	log.Println("Service enumeration workers have completed.")
	wr.PrimaryScanners(project, enumWg)
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

			// Normal "run" (runs once)
			ctx, cancel := context.WithCancel(context.Background())
			dw.CancelFunc = cancel
			defer cancel() // Ensure cleanup

			cmdObj, outChan, stderrChan, errChan, startErr := runCommandCtx(ctx, dw.Command, dw.Args)
			dw.Cmd = cmdObj

			if startErr != nil {
				dw.ErrorChan <- startErr
				dw.WorkerResponse <- ""
				close(dw.WorkerResponse) // Safe to close here as no further sends
				dw.Finished = time.Now()
				return
			}

			// Handle the command output asynchronously
			go func() {
				// Wait for the results
				stdout := <-outChan
				stderr := <-stderrChan
				err := <-errChan

				// Send results to channels
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

				// Close WorkerResponse after all sends are complete
				close(dw.WorkerResponse)
			}()

			// Trigger the worker
			select {
			case dw.UserCommand <- "run":
			default:
				// Channel not ready, proceed anyway
			}
		}(w)
	}
	return &wg
}

func (wr *wranglerRepository) ServiceEnumeration(project *models.Project, discWg *sync.WaitGroup) *sync.WaitGroup {
	enumDir := path.Join(project.ReportDir, project.Name, "enumeration")
	err := os.MkdirAll(enumDir, 600)
	if err != nil {
		fmt.Printf("failed to create enum dir: %s", err)
		return nil
	}

	w := models.Worker{
		ID:             1,
		Type:           "nmap",
		Command:        "nmap",
		Description:    "Host service  all ports enumeration scans",
		UserCommand:    make(chan string, 1),
		WorkerResponse: make(chan string),
		ErrorChan:      make(chan error),
	}

	args := []string{"-sTV", "-p-"}
	w.Args = append(w.Args, args...)
	project.Workers = []models.Worker{w}

	wg := wr.startWorkers(project, serviceEnum, batchSize)

	// Setup signal handling & error watchers
	wr.SetupSignalHandler(project.Workers, sigCh)
	wr.DrainWorkerErrors(project.Workers, errCh)
	wr.ListenToWorkerErrors(project.Workers, errCh)

	if discWg != nil {
		discWg.Wait()
		log.Println("All discovery workers have finished.")
	}

	//wg.Wait()
	//log.Println("HostService enumeration workers have stopped.")

	if wr.cli.DebugWorkers {
		debugWorkers(project.Workers)
	}
	return wg
}

func (wr *wranglerRepository) PrimaryScanners(project *models.Project, enumWg *sync.WaitGroup) *sync.WaitGroup {
	// Load patterns from YAML
	args, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("Unable to load scans: %s", err.Error())
		//enumWg.Done()
		return nil
	}
	log.Printf("Loaded primary %d scans from YAML", len(args))

	// Build "primaryWorkers" from YAML
	for i, pattern := range args {
		wk := models.Worker{
			ID:             i,
			Type:           pattern.Tool,
			Command:        pattern.Tool,
			Args:           pattern.Args,
			Description:    pattern.Description,
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string),
			ErrorChan:      make(chan error),
		}
		primaryWorkers = append(primaryWorkers, wk)
	}

	project.Workers = primaryWorkers
	wg := wr.startWorkers(project, fullScan, batchSize)

	// Setup signal handling & error watchers
	wr.SetupSignalHandler(project.Workers, sigCh)
	wr.DrainWorkerErrors(project.Workers, errCh)
	wr.ListenToWorkerErrors(project.Workers, errCh)

	//if enumWg != nil {
	//	enumWg.Wait()
	//}

	wg.Wait()
	log.Println("All primary scanners have completed.")

	if wr.cli.DebugWorkers {
		debugWorkers(project.Workers)
	}
	return wg
}

func (wr *wranglerRepository) MapWorkersToTarget(baseWorkers []models.Worker) {

}
