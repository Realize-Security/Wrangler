package wrangler

import (
	"Wrangler/pkg/models"
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// DiscoveryWorkersInit sets up one "discovery" worker per host in `inScope`.
func (wr *wranglerRepository) DiscoveryWorkersInit(inScope []string, excludeFile string) (*sync.WaitGroup, chan struct{}) {
	var w []models.Worker
	for i, target := range inScope {
		args := []string{
			"-sn", "-PS22,80,443,3389", "-PA80,443", "-PU40125", "-PY80,443", "-PE", "-PP", "-PM", "-T4", "-v", target,
		}
		w = append(w, models.Worker{
			ID:             i,
			Type:           "nmap",
			Target:         target,
			Command:        "nmap",
			Args:           args,
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string),
			ErrorChan:      make(chan error),
			XMLPathsChan:   make(chan string),
		})
	}

	discoveryDone := wr.DiscoveryResponseMonitor(w, wr.serviceEnum)

	wg := wr.DiscoveryScan(w, excludeFile)

	wr.DrainWorkerErrors(w, errCh)
	wr.ListenToWorkerErrors(w, errCh)
	wr.SetupSignalHandler(w, sigCh)

	return wg, discoveryDone
}

// DiscoveryScan spawns an Nmap -sn job per host. Returns a WaitGroup.
func (wr *wranglerRepository) DiscoveryScan(workers []models.Worker, exclude string) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		w := &workers[i]
		w.Command = "nmap"
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
			dw.UserCommand <- "run"
		}(w)
	}
	return &wg
}
