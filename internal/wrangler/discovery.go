package wrangler

import "sync"

// DiscoveryWorkersInit sets up one "discovery" worker per host in `inScope`.
func (wr *wranglerRepository) DiscoveryWorkersInit(inScope []string, excludeFile string) *sync.WaitGroup {
	unconfirmed := make(chan string)

	// Build discovery workers
	var w []Worker
	for i, target := range inScope {
		args := []string{
			"-sn",
			"-PS22,80,443,3389",
			"-PA80,443",
			"-PU40125",
			"-PY80,443",
			"-PE",
			"-PP",
			"-PM",
			"-T4",
			"-v",
			"--discovery-ignore-rst",
			target,
		}
		w = append(w, Worker{
			ID:             i,
			Type:           "nmap",
			Target:         target,
			Command:        "nmap",
			Args:           args,
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string),
			ErrorChan:      make(chan error),
		})
	}

	// Start reading from their responses
	wr.DiscoveryResponseMonitor(w, unconfirmed, fullScan)

	// Launch them
	wg := wr.HostDiscoveryScan(w, excludeFile)

	// Drain errors & watch for fatal
	wr.DrainWorkerErrors(w, errCh)
	wr.ListenToWorkerErrors(w, errCh)

	// Setup optional timeouts, signals
	wr.WorkerTimeout(w)
	wr.SetupSignalHandler(w, sigCh)

	return wg
}
