package wrangler

import (
	"Wrangler/internal/files"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// DiscoveryResponseMonitor reads `WorkerResponse` from each discovery worker.
// If the nmap output indicates "Host is up", we send that host to `fullScan`.
// Otherwise, we send it to `unknownHosts`.
func (wr *wranglerRepository) DiscoveryResponseMonitor(workers []Worker, unknownHosts, fullScan chan<- string) {
	var wg sync.WaitGroup
	wg.Add(len(workers))

	for _, w := range workers {
		w := w
		go func() {
			defer wg.Done()
			for resp := range w.WorkerResponse {
				if strings.Contains(resp, "Host is up (") {
					fullScan <- w.Target
				} else {
					unknownHosts <- w.Target
				}
			}
		}()
	}

	// Wait for all goroutines to finish sending
	go func() {
		wg.Wait()
		// Now it's safe to close these channels, because no one will send anymore
		close(fullScan)
		close(unknownHosts)
	}()
}

// CleanupPermissions adjusts file/directory ownership/permissions recursively.
func (wr *wranglerRepository) CleanupPermissions(reports, scopes string) error {
	fmt.Println("[*] Cleaning up.")
	paths := []string{reports, scopes}

	for _, p := range paths {
		if p == "" {
			continue
		}
		err := files.SetFileAndDirPermsRecursive(nonRootUser, p)
		if err != nil {
			log.Printf("failed to set permissions for %s: %s", p, err.Error())
			return err
		}
	}
	return nil
}

// WorkerTimeout checks if each worker has run longer than `Timeout`.
// If so, it sends "STOP" to that worker.
func (wr *wranglerRepository) WorkerTimeout(workers []Worker) {
	for _, w := range workers {
		w := w
		go func() {
			if time.Since(w.Started) >= w.Timeout {
				w.UserCommand <- WorkerStop
			}
		}()
	}
}

// SetupSignalHandler listens for Ctrl+C or kill signals
// and gracefully stops all workers if such a signal arrives.
func (wr *wranglerRepository) SetupSignalHandler(workers []Worker, sigCh <-chan os.Signal) {
	go func() {
		<-sigCh
		log.Println("Received interrupt signal, stopping workers...")
		for _, w := range workers {
			if w.CancelFunc != nil {
				w.CancelFunc()
			}
			w.UserCommand <- WorkerStop
		}
	}()
}

// DrainWorkerErrors watches each worker's `ErrorChan` until it's closed.
// If a non-nil error arrives, we send it to `errCh`.
func (wr *wranglerRepository) DrainWorkerErrors(workers []Worker, errCh chan<- error) {
	for _, w := range workers {
		// capture w in closure
		w := w
		go func() {
			for workerErr := range w.ErrorChan {
				if workerErr != nil {
					errCh <- fmt.Errorf("worker %d encountered an OS error: %w", w.ID, workerErr)
				}
			}
		}()
	}
}

// ListenToWorkerErrors receives the first error from any worker on `errCh`,
// logs it, and immediately sends "STOP" to all workers.
func (wr *wranglerRepository) ListenToWorkerErrors(workers []Worker, errCh <-chan error) {
	go func() {
		err := <-errCh
		log.Printf("FATAL: %v", err)
		for _, w := range workers {
			if w.CancelFunc != nil {
				w.CancelFunc()
			}
			w.UserCommand <- WorkerStop
		}
	}()
}
