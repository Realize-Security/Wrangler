package wrangler

import (
	"Wrangler/internal/nmap"
	"Wrangler/pkg/concurrency"
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
// Returns a channel that is closed when all processing is complete.
func (wr *wranglerRepository) DiscoveryResponseMonitor(workers []models.Worker) {
	var wg sync.WaitGroup
	wg.Add(len(workers))

	for _, w := range workers {
		w := w
		go func() {
			for resp := range w.WorkerResponse {
				if strings.Contains(resp, "Host is up (") {
					hosts := getUpHosts(resp)
					for _, host := range hosts {
						if host != "" {
							log.Printf("[*] Found live host: %s", host)
							t := models.Target{Host: host}
							wr.staticTargets.Add(t)
							wr.serviceEnum.Add(t)
						} else {
							// If we've hit an empty string, the rest of the []string is presumed empty
							log.Println("[*] Empty string in discovery response checks")
							break
						}
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		log.Println("[*] All responses monitored, service enumeration channel closed.")
	}()
}

// MonitorServiceEnum parses each Nmap XML from the service enumeration stage & pushes open hosts/ports.
func (wr *wranglerRepository) MonitorServiceEnum(workers []models.Worker) {
	var wg sync.WaitGroup
	if len(workers) == 0 {
		log.Println("[!] No workers to monitor")
		return
	}

	log.Printf("[*] Starting to monitor %d workers", len(workers))

	for i := range workers {
		w := &workers[i]
		wg.Add(1)
		go func(w *models.Worker) {
			log.Printf("[*] Worker %d: Routine started", w.ID)
			defer func() {
				wg.Done()
				log.Printf("[*] Worker %d: Routine completed", w.ID)
			}()

			xmlPath, ok := <-w.XMLPathsChan
			if !ok {
				log.Printf("[*] XMLPathsChan closed for worker %d", w.ID)
				return
			}

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
						t := models.Target{
							Host:  host.Addresses[0].Addr,
							Ports: openPorts,
						}
						wr.templateTargets.Add(t)
						log.Printf("[*] Sent %s for service enumeration", t.Host)
					}
				}
			}
		}(w)
	}
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
			log.Printf("Received signal: %v. Stopping workers gracefully", sig)
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

// ListenToWorkerErrors receives the first error from any worker on `errCh`,
func (wr *wranglerRepository) ListenToWorkerErrors(workers []models.Worker, errCh <-chan error) {
	go func() {
		for err := range errCh {
			if err != nil {
				log.Printf("FATAL: %v, stopping workers.", err)
				wr.stopWorkers(workers)
				os.Exit(1)
			}
		}
		log.Println("[!] No worker errors received, channel closed.")
	}()
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
						"worker %d encountered an error: %s, stderr: %s",
						w.ID, workerErr.Error(), w.StdError,
					)
				}
			}
		}()
	}

	go func() {
		wg.Wait()
	}()
}

func killProcessGroup(cmd *exec.Cmd, worker *models.Worker) {
	pgid := cmd.Process.Pid
	if pids, err := listProcessesByPGID(pgid); err == nil && len(pids) > 0 {
		log.Printf("worker-%s: Found %d remaining processes in group %d after cmd.Wait(), attempting to kill", worker.ID, len(pids), pgid)
		if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
			log.Printf("worker-%s: Failed to kill process group %d: %v", worker.ID, pgid, err)
		}
		// Wait briefly and check again
		time.Sleep(1 * time.Second)
		if pids, err := listProcessesByPGID(pgid); err == nil && len(pids) > 0 {
			log.Printf("worker-%s: WARNING: Still %d processes in group %d after attempting to kill", worker.ID, len(pids), pgid)
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

// GracefulCloseDown gracefully shuts down by signaling to stop discovery
// and service enumeration, then draining all registries
func (w *wranglerRepository) GracefulCloseDown() {
	discoveryDone.Store(true)
	serviceEnumDone.Store(true)

	log.Println("Starting graceful shutdown")

	drainRegistryWorker(w.staticWorkers, "Static Workers")
	drainRegistryWorker(w.templateWorkers, "Template Workers")

	drainRegistryTarget(w.serviceEnum, "Service Enumeration")
	drainRegistryTarget(w.staticTargets, "Static Targets")
	drainRegistryTarget(w.templateTargets, "Template Targets")

	log.Println("Graceful shutdown completed")
}

// drainRegistryWorker empties a registry of workers
func drainRegistryWorker(registry *concurrency.Registry[models.Worker], name string) {
	if registry == nil {
		log.Printf("Registry %s is nil, skipping", name)
		return
	}

	log.Printf("Draining %s registry", name)

	totalCount := registry.Len()
	log.Printf("%s registry has %d items to drain", name, totalCount)

	const batchSize = 100

	itemsDrained := 0
	for {
		batch := registry.ReadAndRemoveNFromRegistry(batchSize)
		batchSize := len(batch)
		if batchSize == 0 {
			break
		}

		itemsDrained += batchSize
		log.Printf("Drained %d/%d items from %s registry", itemsDrained, totalCount, name)

		// Process the workers and clean up resources
		for _, worker := range batch {
			// Cancel the context if it exists
			if worker.CancelFunc != nil {
				log.Printf("Canceling context for worker %d", worker.ID)
				worker.CancelFunc()
			}

			// Send stop command if available
			if worker.UserCommand != nil {
				select {
				case worker.UserCommand <- WorkerStop:
					log.Printf("Sent STOP to worker %d", worker.ID)
				case <-time.After(1 * time.Second):
					log.Printf("Timeout sending STOP to worker %d", worker.ID)
				}
			}

			// Close channels if they're not nil and not already closed
			safelyCloseChannel(worker.WorkerResponse, fmt.Sprintf("worker %d WorkerResponse", worker.ID))
			safelyCloseChannel(worker.XMLPathsChan, fmt.Sprintf("worker %d XMLPathsChan", worker.ID))
			safelyCloseChannel(worker.ErrorChan, fmt.Sprintf("worker %d ErrorChan", worker.ID))

			// If worker has a command that's still running, try to kill the process group
			if worker.Cmd != nil && worker.Cmd.Process != nil {
				pgid := worker.Cmd.Process.Pid
				log.Printf("Attempting to kill process group for worker %d (PGID: %d)", worker.ID, pgid)
				if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
					log.Printf("Failed to kill process group for worker %d: %v", worker.ID, err)
				}
			}
		}
	}

	remainingCount := registry.Len()
	if remainingCount > 0 {
		log.Printf("WARNING: %s registry still has %d items after draining", name, remainingCount)
	} else {
		log.Printf("%s registry successfully drained", name)
	}
}

// safelyCloseChannel safely closes a channel if it's not nil and not already closed
// This uses a recover to avoid panics from closing already-closed channels
func safelyCloseChannel(ch interface{}, name string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("WARNING: Recovered from panic while closing %s: %v", name, r)
		}
	}()

	if ch == nil {
		return
	}

	switch c := ch.(type) {
	case chan string:
		if c != nil {
			close(c)
			log.Printf("Closed string channel: %s", name)
		}
	case chan error:
		if c != nil {
			close(c)
			log.Printf("Closed error channel: %s", name)
		}
	case chan struct{}:
		if c != nil {
			close(c)
			log.Printf("Closed struct{} channel: %s", name)
		}
	default:
		log.Printf("Unknown channel type for %s, not closing", name)
	}
}

// drainRegistryTarget empties a registry of targets
func drainRegistryTarget(registry *concurrency.Registry[models.Target], name string) {
	if registry == nil {
		log.Printf("Registry %s is nil, skipping", name)
		return
	}

	log.Printf("Draining %s registry", name)

	totalCount := registry.Len()
	log.Printf("%s registry has %d items to drain", name, totalCount)

	const batchSize = 100

	itemsDrained := 0
	for {
		batch := registry.ReadAndRemoveNFromRegistry(batchSize)
		batchSize := len(batch)
		if batchSize == 0 {
			break
		}

		itemsDrained += batchSize
		log.Printf("Drained %d/%d items from %s registry", itemsDrained, totalCount, name)
	}

	remainingCount := registry.Len()
	if remainingCount > 0 {
		log.Printf("WARNING: %s registry still has %d items after draining", name, remainingCount)
	} else {
		log.Printf("%s registry successfully drained", name)
	}
}
