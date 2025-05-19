package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/models"
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

func (wr *wranglerRepository) DiscoveryWorkersInit(templates []models.Worker, inScope []string, scopeDir string) {
	workers := wr.createDiscoveryWorkers(templates, inScope, scopeDir)
	if len(workers) == 0 {
		log.Println("[!] No discovery workers were initialized")
		return
	}
	wr.startAndMonitorWorkers(workers)
}

func (wr *wranglerRepository) createDiscoveryWorkers(templates []models.Worker, inScope []string, scopeDir string) []models.Worker {
	var workers []models.Worker

	// Create chunk files and workers for each chunk
	for i, chunk := range chunkSlice(inScope, batchSize) {
		chunkFile, err := wr.createChunkFile(scopeDir, i, chunk)
		if err != nil {
			continue
		}

		// Create a worker from each template
		for _, tmpl := range templates {
			worker := wr.createWorkerFromTemplate(tmpl, chunkFile)
			workers = append(workers, worker)
		}
	}

	return workers
}

func (wr *wranglerRepository) createWorkerFromTemplate(template models.Worker, scopeFile string) models.Worker {
	// Create a deep copy of the template
	worker := wr.DuplicateWorker(&template)

	// Add scope arguments
	worker.Args = append(worker.Args, worker.ScopeArg, scopeFile)
	return worker
}

func (wr *wranglerRepository) startAndMonitorWorkers(workers []models.Worker) {
	var wg sync.WaitGroup
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

func (wr *wranglerRepository) createChunkFile(dir string, index int, chunk []string) (string, error) {
	filename := fmt.Sprintf("%s_%d.txt", project.TempPrefix, index)
	path, err := files.WriteSliceToFile(dir, filename, chunk)
	if err != nil {
		log.Printf("[!] Unable to create temp scope file: %s", err)
		return "", err
	}
	return path, nil
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
