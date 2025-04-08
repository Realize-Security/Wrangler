package wrangler

import (
	"Wrangler/pkg/models"
	"sync"
)

// DiscoveryWorkersInit sets up one "discovery" worker per host in `inScope`.
func (wr *wranglerRepository) DiscoveryWorkersInit(inScope []string, excludeFile string) (*sync.WaitGroup, chan struct{}) {
	var w []models.Worker
	for i, target := range inScope {
		args := []string{
			"-sn", "-PS22,80,443,3389", "-PA80,443", "-PU40125", "-PY80,443", "-PE", "-PP", "-PM", "-T4", "-v", target,
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
			XMLPathsChan:   make(chan string),
		})
	}

	// Start monitoring responses and get done channel
	discoveryDone := wr.DiscoveryResponseMonitor(w, serviceEnum)

	// Start discovery workers
	wg := wr.DiscoveryScan(w, excludeFile)

	// Setup error and signal handlers
	wr.DrainWorkerErrors(w, errCh)
	wr.ListenToWorkerErrors(w, errCh)
	wr.SetupSignalHandler(w, sigCh)

	return wg, discoveryDone
}
