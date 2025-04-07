package wrangler

import (
	"Wrangler/pkg/models"
	"fmt"
	"github.com/shirou/gopsutil/v3/process"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DiscoveryResponseMonitor reads `WorkerResponse` from each discovery worker.
// If the nmap output indicates "Host is up", we send that host to `serviceEnum`.
func (wr *wranglerRepository) DiscoveryResponseMonitor(workers []models.Worker, serviceEnum chan<- string) {
	var wg sync.WaitGroup
	wg.Add(len(workers))

	for _, w := range workers {
		w := w
		go func() {
			defer wg.Done()
			for resp := range w.WorkerResponse {
				if strings.Contains(resp, "Host is up (") {
					serviceEnum <- w.Target
				}
			}
		}()
	}

	// Wait for all goroutines to finish sending
	go func() {
		wg.Wait()
		close(serviceEnum)
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
		//err := files.SetFileAndDirPermsRecursive(nonRootUser, p)
		//if err != nil {
		//	log.Printf("failed to set permissions for %s: %s", p, err.Error())
		//	return err
		//}
	}
	return nil
}

func (wr *wranglerRepository) SetupSignalHandler(workers []models.Worker, sigCh <-chan os.Signal) {
	go func() {
		for sig := range sigCh {
			log.Printf("Received signal %v, stopping workers...", sig)
			wr.stopWorkers(workers)
		}
	}()
}

func (wr *wranglerRepository) stopWorkers(workers []models.Worker) {
	commands := make(map[string]bool)
	for _, w := range workers {
		if w.CancelFunc != nil {
			w.CancelFunc()
		}
		if w.Cmd != nil && w.Cmd.Process != nil {
			err := syscall.Kill(-w.Cmd.Process.Pid, syscall.SIGKILL)
			if err != nil {
				commands[w.Command] = true
			}
		}
		if w.UserCommand != nil {
			select {
			case w.UserCommand <- WorkerStop:
			case <-time.After(1 * time.Second):
			}
		}
		processWipe(commands)
	}
}

// DrainWorkerErrors watches each worker's `ErrorChan` until it's closed.
// If a non-nil error arrives, we send it to `errCh`.
func (wr *wranglerRepository) DrainWorkerErrors(workers []models.Worker, errCh chan<- error) {
	for _, w := range workers {
		// capture w in closure
		w := w
		go func() {
			for workerErr := range w.ErrorChan {
				if workerErr != nil {
					errCh <- fmt.Errorf("worker %d encountered an OS error: %w", w.ID, workerErr)
					if w.StdError != "" {
						fmt.Printf("stderror: %s", w.StdError)
					}
				}
			}
		}()
	}
}

// ListenToWorkerErrors receives the first error from any worker on `errCh`,
// logs it, and immediately sends "STOP" (and SIGKILL) to all workers.
func (wr *wranglerRepository) ListenToWorkerErrors(workers []models.Worker, errCh <-chan error) {
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

func killProcessesByName(target string) error {
	parts := strings.Split(target, "/")
	target = parts[len(parts)-1]
	procs, err := process.Processes()
	if err != nil {
		return fmt.Errorf("could not list processes: %w", err)
	}

	var killedCount int

	for _, proc := range procs {
		pname, err := proc.Name()
		if err != nil {
			continue
		}

		if strings.EqualFold(pname, target) {
			pid := proc.Pid
			err := proc.Kill()
			if err != nil {
				log.Printf("Failed to kill %s (PID %d): %v", pname, pid, err)
			} else {
				log.Printf("Killed %s (PID %d)", pname, pid)
				killedCount++
			}
		}
	}

	if killedCount == 0 {
		log.Printf("No processes found with name: %s", target)
	}
	return nil
}

func processWipe(commands map[string]bool) {
	for key := range commands {
		err := killProcessesByName(key)
		if err != nil {
			fmt.Println(err)
		}
	}
}
