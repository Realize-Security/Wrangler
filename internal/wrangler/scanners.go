package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/internal/nmap"
	"Wrangler/pkg/models"
	"fmt"
	"log"
	"os"
	"sync"
)

func (wr *wranglerRepository) startScanProcess(
	project *models.Project,
	inScope []string,
	exclude string,
) {
	tempDir, err := files.MakeTempDir(project.ProjectBase, project.TempPrefix)
	if err != nil {
		fmt.Printf("unable to create temp scope file directory: %s", err)
	}

	defer func(name string) {
		err = os.RemoveAll(name)
		if err != nil {
			fmt.Printf("unable to delete temp scope file directory: %s", err)
		}
	}(tempDir)

	// Step 1: Run host discovery and block until complete
	log.Println("[*] Starting discovery")
	discoveryWg := wr.DiscoveryWorkersInit(inScope, exclude, tempDir, project)
	if discoveryWg != nil {
		log.Println("[DEBUG] Waiting for discovery to complete")
		discoveryWg.Wait()
		log.Println("[DEBUG] Discovery complete")
	}

	// Step 2: Start static workers AFTER discovery is complete to use allUpHosts
	log.Println("[*] Starting static worker templates")
	staticWg := wr.StaticScanners(project, wr.staticWorkers)

	// Step 3: Start service enumeration
	log.Println("[*] Starting ServiceEnumeration")
	parseWg, enumWg := wr.ServiceEnumeration(project)

	// Step 4: Start primary scanners after service enumeration in a goroutine
	primaryDone := make(chan struct{})
	go func() {
		// Wait for static scanners to complete
		if staticWg != nil {
			log.Println("[DEBUG] Waiting for static workers to complete")
			staticWg.Wait()
			log.Println("[DEBUG] Static workers complete")
		}

		log.Println("[DEBUG] Waiting for service enumeration to complete")
		enumWg.Wait()
		parseWg.Wait()
		log.Println("[*] Service enumeration complete, closing fullScan channel")
		close(wr.fullScan)

		log.Println("[*] Starting template-based TemplateScanners")
		primaryWg := wr.TemplateScanners(project, wr.templateWorkers)
		if primaryWg != nil {
			log.Println("[DEBUG] Waiting for primary scanners to complete")
			primaryWg.Wait()
			log.Println("[DEBUG] Primary scanners complete")
		}
		close(primaryDone)
	}()

	// Main goroutine returns immediately, not blocking
	log.Println("[*] Scanning initiated, running in background")
}

func (wr *wranglerRepository) ServiceEnumeration(project *models.Project) (*sync.WaitGroup, *sync.WaitGroup) {
	wTCP := models.Worker{
		ID:             1,
		Type:           "nmap",
		Command:        "nmap",
		Protocol:       "tcp",
		Description:    "TCP service discovery scan",
		UserCommand:    make(chan string, 1),
		WorkerResponse: nil,
		ErrorChan:      make(chan error),
		XMLPathsChan:   make(chan string),
	}

	wUDP := models.Worker{
		ID:             2,
		Type:           "nmap",
		Command:        "nmap",
		Protocol:       "udp",
		Description:    "UDP service discovery scan",
		UserCommand:    make(chan string, 1),
		WorkerResponse: nil,
		ErrorChan:      make(chan error),
		XMLPathsChan:   make(chan string),
	}

	// Configure TCP command
	tcpCmd := nmap.NewCommand(nmap.TCP, "-p-", nil)
	tcpCmd.Add().
		MinHostGroup(100).
		MinRate(150).
		MaxRetries(2)

	// Configure UDP command
	udpCmd := nmap.NewCommand(nmap.UDP, "", nil)
	udpCmd.Add().
		MinHostGroup(100).
		MinRate(150).
		MaxRetries(2).
		TopPorts(1000)

	// Assign arguments to workers
	wTCP.Args = tcpCmd.ToArgList()
	wUDP.Args = udpCmd.ToArgList()

	workers := []models.Worker{wTCP, wUDP}

	enumWg := wr.startWorkers(project, workers, wr.serviceEnum, batchSize)
	log.Println("[*] Workers started...")

	parseWg := wr.MonitorServiceEnum(workers)
	log.Println("[*] Service enumeration started...")

	wr.SetupSignalHandler(workers, sigCh)
	wr.DrainWorkerErrors(workers, errCh)
	wr.ListenToWorkerErrors(workers, errCh)

	return parseWg, enumWg
}

func (wr *wranglerRepository) StaticScanners(project *models.Project, workers []models.Worker) *sync.WaitGroup {
	if len(allUpHosts) > 0 {
		log.Printf("[*] Starting %d static workers", len(workers))
	} else {
		log.Print("[!] No hosts discovered")
		return nil
	}

	ch := make(chan models.Target, len(allUpHosts))
	for _, host := range allUpHosts {
		ch <- models.Target{Host: host}
	}

	wg := wr.startWorkers(project, workers, ch, batchSize)
	if wg == nil {
		log.Println("[!] No workers returned for primary scanners")
		return &sync.WaitGroup{}
	}

	wr.SetupSignalHandler(workers, sigCh)
	wr.DrainWorkerErrors(workers, errCh)
	wr.ListenToWorkerErrors(workers, errCh)

	log.Println("[*] Primary scanners running")
	return wg
}

func (wr *wranglerRepository) TemplateScanners(project *models.Project, workers []models.Worker) *sync.WaitGroup {
	if len(workers) == 0 {
		log.Println("[!] No workers, skipping")
		var wg sync.WaitGroup
		go func() {
			for t := range wr.fullScan {
				log.Printf("[*] Draining target %s with ports %v", t.Host, t.Ports)
			}
		}()
		return &wg
	}

	log.Printf("[*] Starting %d workers", len(workers))

	wg := wr.startWorkers(project, workers, wr.fullScan, batchSize)
	if wg == nil {
		log.Println("[!] No workers returned for primary scanners")
		return &sync.WaitGroup{}
	}

	wr.SetupSignalHandler(workers, sigCh)
	wr.DrainWorkerErrors(workers, errCh)
	wr.ListenToWorkerErrors(workers, errCh)

	log.Println("[*] Primary scanners running")
	return wg
}
