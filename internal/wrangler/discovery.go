package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/internal/nmap"
	"Wrangler/pkg/models"
	"context"
	"fmt"
	"github.com/google/uuid"
	"log"
	"strconv"
	"sync"
	"time"
)

// DiscoveryWorkersInit sets up one "discovery" worker per host in `inScope`.
func (wr *wranglerRepository) DiscoveryWorkersInit(inScope []string, scopeDir string) {
	var workers []models.Worker
	var wg sync.WaitGroup

	for i, chunk := range chunkSlice(inScope, batchSize) {
		f, err := files.WriteSliceToFile(scopeDir, project.TempPrefix+"_"+strconv.Itoa(i)+".txt", chunk)
		if err != nil {
			fmt.Printf("unable to create temp scope file: %s", err)
		}

		cmd := nmap.NewCommand("-sn")
		cmd.Add().
			Custom("-PS21,22,80,443,3389", "").
			Custom("-PA80,443", "").
			Custom("-PU40125", "").
			Custom("-PY80,443", "").
			Custom("-PE", "").
			Custom("-PP", "").
			Custom("-PM", "").
			PerformanceTemplate(nmap.Aggressive).
			InputFile(f).
			NoResolve().
			Verbose(nmap.VerbosityLow).
			MaxRetries(2)

		args := cmd.ToArgList()

		// TODO: Refactor to use NewWorkerNoService() function
		workers = append(workers, models.Worker{
			ID:             uuid.Must(uuid.NewUUID()),
			Tool:           nmap.BinaryName,
			Args:           args,
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string),
			ErrorChan:      make(chan error),
			XMLPathsChan:   make(chan string),
		})
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
		w.Tool = nmap.BinaryName

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
