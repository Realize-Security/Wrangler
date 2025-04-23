package wrangler

import (
	"Wrangler/internal/nmap"
	"Wrangler/pkg/helpers"
	"Wrangler/pkg/models"
	"fmt"
	"github.com/shirou/gopsutil/v4/process"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DiscoveryResponseMonitor reads `WorkerResponse` from each discovery worker.
// If the nmap output indicates "Host is up", we send that host to `serviceEnum`.
func (wr *wranglerRepository) DiscoveryResponseMonitor(workers []models.Worker) {
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
							log.Printf("[*] Found live host: %s", hosts)
							wr.serviceEnum <- models.Target{Host: host}
							allUpHosts = append(allUpHosts, host)
						} else {
							// If we've hit an empty string, the rest of the []string is presumed empty
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
}

// MonitorServiceEnum parses each Nmap XML from
// the service-enumeration stage & pushes open hosts/ports
// onto `fullScan` channel immediately.
func (wr *wranglerRepository) MonitorServiceEnum(
	workers []models.Worker,
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
					var openPorts []models.NmapPort
					for _, p := range host.Ports.Port {
						if p.State.State == "open" {
							openPorts = append(openPorts, p)
						}
					}
					if len(openPorts) > 0 {
						log.Printf("[*] Found %s -> Ports: %v", host.Addresses[0].Addr, openPorts)
						t := models.Target{
							Host:  host.Addresses[0].Addr,
							Ports: openPorts,
						}
						wr.fullScan <- t
						log.Printf("[*] Sent %s to fullScan", t.Host)
					}
				}
			}
			log.Printf("[*] XML processed for worker %d", w.ID)
		}(w)
	}
	return &wg
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
	for _, w := range workers {
		if w.CancelFunc != nil {
			log.Printf("Canceling context for worker %d", w.ID)
			w.CancelFunc()
		}
		if w.UserCommand != nil {
			select {
			case w.UserCommand <- WorkerStop:
				log.Printf("Sent STOP to worker %d", w.ID)
			case <-time.After(1 * time.Second):
				log.Printf("Timeout sending STOP to worker %d", w.ID)
			}
		}
	}
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
						"worker %d encountered an OS error: %s, stderr: %s",
						w.ID, workerErr.Error(), w.StdError,
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

func killProcessGroup(cmd *exec.Cmd, worker *models.Worker) {
	pgid := cmd.Process.Pid
	if pids, err := listProcessesByPGID(pgid); err == nil && len(pids) > 0 {
		log.Printf("worker-%d: Found %d remaining processes in group %d after cmd.Wait(), attempting to kill", worker.ID, len(pids), pgid)
		if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
			log.Printf("worker-%d: Failed to kill process group %d: %v", worker.ID, pgid, err)
		}
		// Wait briefly and check again
		time.Sleep(1 * time.Second)
		if pids, err := listProcessesByPGID(pgid); err == nil && len(pids) > 0 {
			log.Printf("worker-%d: WARNING: Still %d processes in group %d after attempting to kill", worker.ID, len(pids), pgid)
		}
	}
}

func listProcessesByPGID(pgid int) ([]int, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, p := range procs {
		if pgidInt, err := p.Ppid(); err == nil && pgidInt == int32(pgid) {
			pids = append(pids, int(p.Pid))
		}
	}
	return pids, nil
}
