package wrangler

import (
	"Wrangler/pkg/models"
	"sync"
)

// DiscoveryWorkersInit sets up one "discovery" worker per host in `inScope`.
func (wr *wranglerRepository) DiscoveryWorkersInit(inScope []string, excludeFile string) *sync.WaitGroup {
	var w []models.Worker
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
			//"--discovery-ignore-rst",
			target,
		}
		w = append(w, models.Worker{
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

	// Monitor each worker's WorkerResponse & send discovered hosts to serviceEnum
	wr.DiscoveryResponseMonitor(w, serviceEnum)

	// Actually start the "discovery" nmap -sn workers
	wg := wr.HostDiscoveryScan(w, excludeFile)

	// Error watchers and signals
	wr.DrainWorkerErrors(w, errCh)
	wr.ListenToWorkerErrors(w, errCh)
	wr.SetupSignalHandler(w, sigCh)

	return wg
}
