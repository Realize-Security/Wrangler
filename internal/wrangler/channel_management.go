package wrangler

import (
	"Wrangler/internal/nmap"
	"Wrangler/pkg/helpers"
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
func (wr *wranglerRepository) DiscoveryResponseMonitor(workers []models.Worker) chan struct{} {
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
					hosts := getUpHosts(resp)
					for _, host := range hosts {
						if host != "" {
							wr.serviceEnum <- models.Target{Host: host}
							log.Printf("[*] Found live host: %s", hosts)
						} else {
							// If we've hit a "", the rest of the []string is empty
							break
						}
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(wr.serviceEnum)
		log.Println("[*] All responses monitored, service enumeration channel closed.")
		close(done)
	}()
	return done
}

// getUpHosts extract IPv4 addresses from Nmap stdout
func getUpHosts(output string) []string {
	lines := strings.Split(output, "\n")
	res := make([]string, len(lines))
	i := 0
	for _, line := range lines {
		if !strings.HasPrefix(line, "Nmap scan report for") {
			continue
		}
		if strings.HasSuffix(line, "[host down]") {
			continue
		}
		ip := helpers.ExtractIPv4FromString(line)
		res[i] = ip
		i++
	}
	if len(res) > 0 {
		return res
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
			w.CancelFunc()
		}
		if w.Cmd != nil && w.Cmd.Process != nil {
			log.Printf("Sending SIGTERM to worker %d (PID %d)", w.ID, w.Cmd.Process.Pid)
			err := syscall.Kill(-w.Cmd.Process.Pid, syscall.SIGTERM)
			if err != nil {
				commands[w.Command] = true
			}
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
	var wg sync.WaitGroup

	for _, w := range workers {
		w := w
		wg.Add(1)

		go func() {
			defer wg.Done()

			for workerErr := range w.ErrorChan {
				if workerErr != nil {
					errCh <- fmt.Errorf(
						"worker %d encountered an OS error: %w, stderr: %s",
						w.ID, workerErr, w.StdError,
					)
				}
			}
		}()
	}

	// close error chan so any downstream listener won't block forever.
	go func() {
		wg.Wait()
		close(errCh)
	}()
}

// ListenToWorkerErrors receives the first error from any worker on `errCh`,
func (wr *wranglerRepository) ListenToWorkerErrors(workers []models.Worker, errCh <-chan error) {
	go func() {
		for err := range errCh {
			if err != nil {
				log.Printf("FATAL: %v, stopping workers...", err)
				wr.stopWorkers(workers)
				os.Exit(1)
			}
		}

		log.Println("[!] No worker errors received, channel closed.")
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
	if len(workers) == 0 {
		log.Println("[!] No workers to monitor")
		return &wg
	}

	log.Printf("[*] Starting to monitor %d workers", len(workers))

	for i := range workers {
		w := &workers[i]
		wg.Add(1)
		go func(w *models.Worker) {
			log.Printf("[*] Worker %d goroutine started", w.ID)
			defer func() {
				wg.Done()
				log.Printf("[*] Worker %d goroutine wg.Done() completed", w.ID)
			}()

			log.Printf("[*] Waiting for XML path from worker %d", w.ID)
			xmlPath, ok := <-w.XMLPathsChan
			if !ok {
				log.Printf("[*] XMLPathsChan closed for worker %d", w.ID)
				return
			}

			log.Printf("[*] Received XML path %s from worker %d", xmlPath, w.ID)

			nmapRun, err := nmap.ReadNmapXML(xmlPath)
			if err != nil {
				log.Printf("[!] Unable to parse XML file %s for worker %d: %v", xmlPath, w.ID, err)
				w.ErrorChan <- err
				return
			}

			for _, host := range nmapRun.Hosts {
				if host.Status.State == "up" {
					var openPorts []string
					for _, p := range host.Ports.Port {
						if p.State.State == "open" {
							openPorts = append(openPorts, p.PortID)
						}
					}
					if len(openPorts) > 0 {
						log.Printf("[*] Found %s -> Ports: %v", host.Addresses[0].Addr, openPorts)
						t := models.Target{
							Host:  host.Addresses[0].Addr,
							Ports: openPorts,
						}
						log.Printf("[*] Sending target %s to fullScan", t.Host)
						fullScan <- t
						log.Printf("[*] Sent target %s to fullScan", t.Host)
					}
				}
			}
			log.Printf("[*] Finished processing XML for worker %d", w.ID)
		}(w)
	}
	return &wg
}
