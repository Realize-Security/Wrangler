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
func (wr *wranglerRepository) DiscoveryWorkersInit(templates []models.Worker, inScope []string, scopeDir string) {
	var workers []models.Worker
	var wg sync.WaitGroup

	for i, chunk := range chunkSlice(inScope, batchSize) {
		f, err := files.WriteSliceToFile(scopeDir, project.TempPrefix+"_"+strconv.Itoa(i)+".txt", chunk)
		if err != nil {
			fmt.Printf("unable to create temp scope file: %s", err)
		}

		for _, tw := range templates {
			w := wr.DuplicateWorker(&tw)
			scope := []string{tw.ScopeArg, f}
			w.Args = append(w.Args, scope...)
			workers = append(workers, tw)
		}
	}

	wg.Add(len(workers))

	wr.DiscoveryScan(workers, &wg)
	wr.DiscoveryResponseMonitor(workers)
	wr.DrainWorkerErrors(workers, errCh)
	wr.ListenToWorkerErrors(workers, errCh)
	wr.SetupSignalHandler(workers, sigCh)
}

func (wr *wranglerRepository) DiscoveryScan(workers []models.Worker, wg *sync.WaitGroup) {
	discoveryDone.Store(false)
	for i := range workers {
		w := &workers[i]

		log.Println("[*] Host discovery started")
		go func(dw *models.Worker) {
			defer wg.Done()
			dw.Started = time.Now()

			ctx, cancel := context.WithCancel(context.Background())
			dw.CancelFunc = cancel

			cmdObj, outChan, stderrChan, errChan, startErr := runCommandCtx(ctx, dw, dw.Args)
			dw.Cmd = cmdObj

			if startErr != nil {
				log.Printf("Worker %s: Start failed: %v", dw.ID.String(), startErr)
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

	go func() {
		wg.Wait()
		log.Println("[*] Host discovery complete")
		discoveryDone.Store(true)
	}()
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
