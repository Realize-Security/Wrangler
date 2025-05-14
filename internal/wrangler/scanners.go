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

	// Step 1: Run host discovery
	wr.DiscoveryWorkersInit(inScope, exclude, tempDir, project)

	// Step 2: Start static workers
	wr.StaticScanners(project, wr.staticWorkers.GetAll())

	// Step 3: Start  service enumeration
	wr.ServiceEnumeration(project)

	// Step 4: Start primary scanners
	wr.TemplateScanners(project, wr.templateWorkers.GetAll())

	log.Println("[*] Scanning initiated, running in background")
}

func (wr *wranglerRepository) ServiceEnumeration(project *models.Project) {
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
		tcpCmd := nmap.NewCommand(nmap.TCP, "-p-", nil)
		tcpCmd.Add().
			MinHostGroup(100).
			MinRate(150).
			MaxRetries(2)

		desc := "TCP service discovery scan"
		wTCP := NewWorker("nmap", nil, nmap.TCP, desc)
		wTCP.Args = tcpCmd.ToArgList()

		// Configure UDP command
		udpCmd := nmap.NewCommand(nmap.UDP, "", nil)
		udpCmd.Add().
			MinHostGroup(100).
			MinRate(150).
			MaxRetries(2).
			TopPorts(1000)

		desc = "UDP service discovery scan"
		wUDP := NewWorker("nmap", nil, nmap.UDP, desc)
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

func (wr *wranglerRepository) StaticScanners(project *models.Project, workers []models.Worker) {
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

func (wr *wranglerRepository) TemplateScanners(project *models.Project, workers []models.Worker) {
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
