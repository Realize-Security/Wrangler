package wrangler

import (
	"Wrangler/internal/files"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

func (wr *wranglerRepository) DiscoveryResponseMonitor(
	workers []Worker,
	unknownHosts, fullScan chan<- string,
) {
	for _, w := range workers {
		w := w
		go func() {
			for resp := range w.WorkerResponse {
				log.Printf("[Worker %d] %s\n", w.ID, resp)

				// These hosts have responded to ICMP
				if strings.Contains(resp, "Host is up (") {
					fullScan <- w.Target
					finalisedTargets = append(finalisedTargets, w.Target)
					continue
				}
				unknownHosts <- w.Target
			}
		}()
	}
}

func (wr *wranglerRepository) CleanupPermissions(reports, scopes string) error {
	fmt.Println("[*] Cleaning up.")
	paths := []string{reports, scopes}

	for _, p := range paths {
		if p == "" {
			continue
		}
		err := files.SetFileAndDirPermsRecursive(nonRootUser, projectRoot, p)
		if err != nil {
			log.Printf("failed to set permissions for %s: %s", p, err.Error())
			return err
		}
	}
	return nil
}

// WorkerTimeout cancels workers which exceed a set (optional) duration
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

// DrainWorkerErrors watches ErrorChan of each Worker.
// It drains all errors until the channel is closed.
// If a non-nil error arrives, we send it to errCh.
func (wr *wranglerRepository) DrainWorkerErrors(workers []Worker, errCh chan<- error) {
	for _, w := range workers {
		w := w
		go func() {
			// Listen for any errors until the channel is closed.
			for workerErr := range w.ErrorChan {
				if workerErr != nil {
					errCh <- fmt.Errorf("worker %d encountered an OS error: %w", w.ID, workerErr)
				}
			}
		}()
	}
}

// ListenToWorkerErrors will receive the first error from any worker,
// log it, and immediately stop all workers.
func (wr *wranglerRepository) ListenToWorkerErrors(workers []Worker, errCh <-chan error) {
	go func() {
		err := <-errCh
		log.Printf("FATAL: %v", err)
		// Force all workers to stop
		for _, w := range workers {
			if w.CancelFunc != nil {
				w.CancelFunc()
			}
			w.UserCommand <- WorkerStop
		}
	}()
}
