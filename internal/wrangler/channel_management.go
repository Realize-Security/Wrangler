package wrangler

import (
	"Wrangler/internal/nmap"
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
func (wr *wranglerRepository) DiscoveryResponseMonitor(workers []models.Worker, serviceEnum chan<- models.Target) chan struct{} {
	var wg sync.WaitGroup
	wg.Add(len(workers))
	done := make(chan struct{})

	for _, w := range workers {
		w := w
		go func() {
			defer wg.Done()
			for resp := range w.WorkerResponse {
				log.Printf("Worker %d: Received %d bytes of response", w.ID, len(resp))
				if strings.Contains(resp, "Host is up (") {
					serviceEnum <- models.Target{Host: w.Target}
					log.Printf("[Discovery] Found live host: %s", w.Target)
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(serviceEnum)
		log.Println("[Discovery] All responses monitored, serviceEnum closed.")
		close(done)
	}()
	return done
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
			log.Printf("Received signal %v, stopping workers gracefully", sig)
			wr.stopWorkers(workers)
		}
	}()
}

func (wr *wranglerRepository) stopWorkers(workers []models.Worker) {
	commands := make(map[string]bool)
	for _, w := range workers {
		if w.CancelFunc != nil {
			w.CancelFunc() // Cancel context, but Nmap should already have output
		}
		if w.Cmd != nil && w.Cmd.Process != nil {
			log.Printf("Sending SIGTERM to worker %d (PID %d)", w.ID, w.Cmd.Process.Pid)
			err := syscall.Kill(-w.Cmd.Process.Pid, syscall.SIGTERM)
			if err != nil {
				commands[w.Command] = true
			}
			time.Sleep(3 * time.Second) // Increased wait for output flush
			if w.Cmd.Process != nil && !w.Cmd.ProcessState.Exited() {
				log.Printf("Worker %d still running, sending SIGKILL", w.ID)
				_ = syscall.Kill(-w.Cmd.Process.Pid, syscall.SIGKILL)
			}
		}
		if w.UserCommand != nil {
			select {
			case w.UserCommand <- WorkerStop:
			case <-time.After(1 * time.Second):
			}
		}
	}
	processWipe(commands)
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
					errCh <- fmt.Errorf("worker %d encountered an OS error: %w, stderr: %s", w.ID, workerErr, w.StdError)
				}
			}
		}()
	}
}

// ListenToWorkerErrors receives the first error from any worker on `errCh`,
func (wr *wranglerRepository) ListenToWorkerErrors(workers []models.Worker, errCh <-chan error) {
	go func() {
		err := <-errCh
		log.Printf("FATAL: %v - Stopping all workers as per design", err)
		wr.stopWorkers(workers)
		close(serviceEnum) // Ensure closure on error
		close(fullScan)
		log.Println("Pipeline halted due to worker failure")
		os.Exit(1)
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
	// Log and return instead of exiting
	log.Println("Process wipe completed, continuing execution")
}

// MonitorServiceEnum parses each Nmap XML from
// the service-enumeration stage & pushes open hosts/ports
// onto `fullScan` channel immediately.
func (wr *wranglerRepository) MonitorServiceEnum(
	workers []models.Worker,
	fullScan chan<- models.Target,
) *sync.WaitGroup {
	var wg sync.WaitGroup
	wg.Add(len(workers)) // We'll have exactly 1 XMLPathsChan read per worker

	for i := range workers {
		w := &workers[i]
		go func(w *models.Worker) {
			defer wg.Done()

			// Block until this worker emits its XML path (or closes)
			xmlPath, ok := <-w.XMLPathsChan
			if !ok {
				return
			}

			// Now parse the .xml to see what’s open
			nmapRun, err := nmap.ReadNmapXML(xmlPath)
			if err != nil {
				fmt.Printf("unable to parse file: %s\n", xmlPath)
				w.ErrorChan <- err
				return
			}

			// For each host with open ports, push to `fullScan`.
			for _, host := range nmapRun.Hosts {
				if host.Status.State == "up" {
					var openPorts []string
					for _, p := range host.Ports.Port {
						if p.State.State == "open" {
							openPorts = append(openPorts, p.PortID)
						}
					}
					if len(openPorts) > 0 {
						fmt.Printf("[Parser] Found %s -> Ports: %v\n",
							host.Addresses[0].Addr, openPorts)
						t := models.Target{
							Host:  host.Addresses[0].Addr,
							Ports: openPorts,
						}
						fullScan <- t
					}
				}
			}
		}(w)
	}
	return &wg
}
