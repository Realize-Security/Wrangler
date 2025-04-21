package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/internal/nmap"
	"Wrangler/pkg/models"
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"
)

// DiscoveryWorkersInit sets up one "discovery" worker per host in `inScope`.
func (wr *wranglerRepository) DiscoveryWorkersInit(inScope []string, excludeFile, scopeDir string, project *models.Project) {
	var workers []models.Worker

	for i, chunk := range chunkSlice(inScope, batchSize) {
		f, err := files.WriteSliceToFile(scopeDir, project.TempPrefix+"_"+strconv.Itoa(i)+".txt", chunk)
		if err != nil {
			fmt.Printf("unable to create temp scope file: %s", err)
			return
		}

		// Configure TCP command
		cmd := nmap.NewCommand("-sn", "-p-", nil)
		cmd.Add().
			Custom("-PS22,80,443,3389", "").
			Custom("-PA80,443", "").
			Custom("-PU40125", "").
			Custom("-PY80,443", "").
			Custom("-PE", "").
			Custom("-PP", "").
			Custom("-PM", "").
			PerformanceTemplate(nmap.Aggressive).
			InputFile(f).
			NoResolve().
			Verbose(nmap.VerbosityLow)
		args := cmd.ToArgList()

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

	wr.DiscoveryResponseMonitor(workers)
	wr.DiscoveryScan(workers, excludeFile)

	wr.DrainWorkerErrors(workers, errCh)
	wr.ListenToWorkerErrors(workers, errCh)
	wr.SetupSignalHandler(workers, sigCh)
}

// DiscoveryScan spawns an Nmap -sn job per host. Returns a WaitGroup.
func (wr *wranglerRepository) DiscoveryScan(workers []models.Worker, exclude string) {
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		w := &workers[i]
		w.Command = "nmap"
		if exclude != "" {
			cmd := nmap.NewCommand("", "", nil)
			cmd.Add().ExcludeFile(exclude)
			w.Args = append(w.Args, cmd.ToArgList()...)
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
