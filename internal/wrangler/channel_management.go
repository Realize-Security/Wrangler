package wrangler

import (
	"Wrangler/internal/files"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
)

// DiscoveryResponseMonitor reads `WorkerResponse` from each discovery worker.
// If the nmap output indicates "Host is up", we send that host to `fullScan`.
func (wr *wranglerRepository) DiscoveryResponseMonitor(workers []Worker, fullScan chan<- string) {
	var wg sync.WaitGroup
	wg.Add(len(workers))

	for _, w := range workers {
		w := w
		go func() {
			defer wg.Done()
			for resp := range w.WorkerResponse {
				if strings.Contains(resp, "Host is up (") {
					fullScan <- w.Target
				}
			}
		}()
	}

	// Wait for all goroutines to finish sending
	go func() {
		wg.Wait()
		close(fullScan)
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

// SetupSignalHandler listens for Ctrl+C or kill signals
// and gracefully stops all workers if such a signal arrives.
func (wr *wranglerRepository) SetupSignalHandler(workers []Worker, sigCh <-chan os.Signal) {
	go func() {
		<-sigCh
		log.Println("Received interrupt signal, stopping workers...")

		for _, w := range workers {
			// Cancel the context if set
			if w.CancelFunc != nil {
				w.CancelFunc()
			}
			// If we have an active Cmd with a process, kill the entire group
			if w.Cmd != nil && w.Cmd.Process != nil {
				_ = syscall.Kill(-w.Cmd.Process.Pid, syscall.SIGKILL)
			}
			// Send STOP to each worker's channel
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
// logs it, and immediately sends "STOP" (and SIGKILL) to all workers.
func (wr *wranglerRepository) ListenToWorkerErrors(workers []Worker, errCh <-chan error) {
	go func() {
		err := <-errCh
		log.Printf("FATAL: %v", err)

		// Kill/stop all workers immediately
		for _, w := range workers {
			if w.CancelFunc != nil {
				w.CancelFunc()
			}
			if w.Cmd != nil && w.Cmd.Process != nil {
				_ = syscall.Kill(-w.Cmd.Process.Pid, syscall.SIGKILL)
			}
			w.UserCommand <- WorkerStop
		}
	}()
}
