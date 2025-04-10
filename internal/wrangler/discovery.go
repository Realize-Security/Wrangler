package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/models"
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"
)

// DiscoveryWorkersInit sets up one "discovery" worker per host in `inScope`.
func (wr *wranglerRepository) DiscoveryWorkersInit(inScope []string, excludeFile, scopeDir string, project *models.Project) (*sync.WaitGroup, chan struct{}) {
	var workers []models.Worker

	for i, chunk := range chunkSlice(inScope, batchSize) {
		f, err := files.WriteSliceToFile(scopeDir, project.TempPrefix+"_"+strconv.Itoa(i)+".txt", chunk)
		if err != nil {
			fmt.Printf("unable to create temp scope file: %s", err)
			return nil, nil
		}

		args := []string{
			"-sn", "-PS22,80,443,3389",
			"-PA80,443", "-PU40125", "-n",
			"-PY80,443", "-PE", "-PP",
			"-PM", "-T4", "-v", "-iL", f,
		}
		workers = append(workers, models.Worker{
			ID:             0,
			Type:           "nmap",
			Command:        "nmap",
			Args:           args,
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string),
			ErrorChan:      make(chan error),
			XMLPathsChan:   make(chan string),
		})
	}

	discoveryDone := wr.DiscoveryResponseMonitor(workers, wr.serviceEnum)

	wg := wr.DiscoveryScan(workers, excludeFile)

	wr.DrainWorkerErrors(workers, errCh)
	wr.ListenToWorkerErrors(workers, errCh)
	wr.SetupSignalHandler(workers, sigCh)

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

// chunkSlice splits the slice `src` into multiple slices of length `chunkSize`. The last chunk may be shorter if there aren't enough elements left.
func chunkSlice(src []string, chunkSize int) [][]string {
	if chunkSize <= 0 {
		return [][]string{src}
	}
	if len(src) == 0 {
		return nil
	}

	var chunks [][]string
	for i := 0; i < len(src); i += chunkSize {
		end := i + chunkSize
		if end > len(src) {
			end = len(src)
		}
		chunks = append(chunks, src[i:end])
	}
	return chunks
}
