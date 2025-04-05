package wrangler

import (
	"sync"
)

func (wr *wranglerRepository) DiscoveryWorkersInit(inScope []string, excludeFile string) *sync.WaitGroup {
	unconfirmed := make(chan string)
	var w []Worker
	// nmap -sn -PS22,80,443,3389 -PA80,443 -PU40125 -PY80,443 -PE -PP -PM -T4 -v --discovery-ignore-rst 192.168.1.0/24
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
			Args:           args,
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string),
			ErrorChan:      make(chan error),
		})
	}
	wr.DiscoveryResponseMonitor(w, unconfirmed, fullScan)
	wg := wr.HostDiscoveryScan(w, excludeFile)

	wr.DrainWorkerErrors(w, errCh)
	wr.ListenToWorkerErrors(w, errCh)
	//go batchProcessDiscovery(unconfirmed, batchSize)
	wr.WorkerTimeout(w)
	wr.SetupSignalHandler(w, sigCh)

	return wg
}
