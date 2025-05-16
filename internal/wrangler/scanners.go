package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/internal/nmap"
	"Wrangler/pkg/models"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// startScanProcess kicks off scanning stage in order
func (wr *wranglerRepository) startScanProcess(inScope []string) {
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

	// Step 1: Run host discovery
	wr.DiscoveryWorkersInit(inScope, tempDir)

	// Step 2: Start static workers
	wr.staticScanners(wr.staticWorkers.GetAll())

	// Step 3: Start  service enumeration
	wr.serviceEnumeration()

	// Step 4: Start primary scanners
	wr.templateScanners(wr.templateWorkers.GetAll())

	log.Println("[*] Scanning initiated, running in background")
}

// serviceEnumeration scans identified hosts to identify open ports and determine what services are listening
func (wr *wranglerRepository) serviceEnumeration() {
	var wg sync.WaitGroup
	serviceEnumDone.Store(false)
	for {
		if discoveryDone.Load() && wr.serviceEnum.Len() == 0 {
			fmt.Println("[*] Static scanners completed")
			return
		}

		if wr.serviceEnum.Len() == 0 {
			// Gently throttle loops
			time.Sleep(time.Second * 2)
			continue
		}
		targets := wr.serviceEnum.ReadAndRemoveNFromRegistry(wr.cli.BatchSize)

		// Configure TCP command
		tcpCmd := nmap.NewCommand(nmap.TCP)
		tcpCmd.Add().
			MinHostGroup(100).
			MinRate(150).
			MaxRetries(2).
			AllPorts()

		desc := "TCP service discovery scan"
		wTCP := wr.NewWorkerNoService(nmap.BinaryName, nil, nmap.TCP, desc)
		wTCP.Args = tcpCmd.ToArgList()

		// Configure UDP command
		udpCmd := nmap.NewCommand(nmap.UDP)
		udpCmd.Add().
			MinHostGroup(100).
			MinRate(150).
			MaxRetries(2).
			TopPorts(1000)

		desc = "UDP service discovery scan"
		wUDP := wr.NewWorkerNoService(nmap.BinaryName, nil, nmap.UDP, desc)
		wUDP.Args = udpCmd.ToArgList()

		workers := []models.Worker{
			wTCP,
			wUDP,
		}
		wg.Add(len(workers))

		log.Println("[*] Starting service enumeration")
		wr.startWorkers(project, workers, targets)
		wr.MonitorServiceEnum(workers)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)

		go func() {
			wg.Wait()
			log.Println("[*] Service enumeration completed")
			serviceEnumDone.Store(true)
		}()
	}
}

// staticScanners are defined as scans within the YAML config file which already have ports assigned and do not require modification.
func (wr *wranglerRepository) staticScanners(workers []models.Worker) {
	var count = 0
	for {
		if discoveryDone.Load() && wr.staticTargets.Len() == 0 {
			fmt.Println("[*] Static scanners completed")
			break
		}

		if wr.staticTargets.Len() == 0 {
			// Gently throttle any loops
			time.Sleep(time.Second * 2)
			continue
		}

		log.Printf("[*] Starting %d static scanners", len(workers))
		targets := wr.staticTargets.ReadAndRemoveNFromRegistry(wr.cli.BatchSize)

		wr.startWorkers(project, workers, targets)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)

		log.Printf("[*] Static scanner %d running", count)
		count++
	}
}

// TemplateScanners are defined as scans within the YAML config file which do not have ports pre-assigned.
// These scans will be dynamically allocated to target services based on the YAML 'service' field value and aliases
func (wr *wranglerRepository) templateScanners(workers []models.Worker) {
	for {
		if serviceEnumDone.Load() && wr.templateTargets.Len() == 0 && wr.serviceEnum.Len() == 0 {
			fmt.Println("[*] Template scanners completed")
			break
		}

		if wr.templateTargets.Len() == 0 {
			// Gently throttle any loops
			time.Sleep(time.Second * 2)
			continue
		}

		if len(workers) == 0 {
			log.Println("[!] No template workers, skipping")
			continue
		}

		targets := wr.templateTargets.ReadAndRemoveNFromRegistry(wr.cli.BatchSize)

		log.Printf("[*] Starting %d template scanners", len(workers))
		wr.startWorkers(project, workers, targets)
		wr.SetupSignalHandler(workers, sigCh)
		wr.DrainWorkerErrors(workers, errCh)
		wr.ListenToWorkerErrors(workers, errCh)
		log.Println("[*] Templated scanners running")
	}
}
