package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/internal/nmap"
	"Wrangler/pkg/helpers"
	"Wrangler/pkg/models"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// NewWorkerNoService creates a new worker NOT mapped to a service
func (wr *wranglerRepository) NewWorkerNoService(scan *models.Scan) models.Worker {
	return wr.returnWorkerInstance(scan)
}

// NewWorkerWithService creates a new worker mapped to a specific service
func (wr *wranglerRepository) NewWorkerWithService(scan *models.Scan) models.Worker {
	return wr.returnWorkerInstance(scan)
}

// DuplicateWorker duplicates an existing worker with a new ID
func (wr *wranglerRepository) DuplicateWorker(worker *models.Worker) models.Worker {
	// Deep copy the args
	argsCopy := make([]string, len(worker.Args))
	copy(argsCopy, worker.Args)

	return models.Worker{
		ID:                 uuidGen.UUIDv1(),
		Tool:               worker.Tool,
		Args:               argsCopy, // Use the copy
		Protocol:           worker.Protocol,
		Description:        worker.Description,
		TargetService:      worker.TargetService,
		IsHostDiscovery:    worker.IsHostDiscovery,
		IsServiceDiscovery: worker.IsServiceDiscovery,
		ScopeArg:           worker.ScopeArg,

		UserCommand:    make(chan string, 1),
		WorkerResponse: make(chan string, 1),
		ErrorChan:      make(chan error, 1),
		XMLPathsChan:   make(chan string, 1),
	}
}

// returnWorkerInstance returns
func (wr *wranglerRepository) returnWorkerInstance(scan *models.Scan) models.Worker {
	wr.appendExclusions(&scan.Args)
	return models.Worker{
		ID:                 uuidGen.UUIDv1(),
		Tool:               scan.Tool,
		Args:               scan.Args,
		Protocol:           scan.Protocol,
		Description:        scan.Description,
		TargetService:      scan.TargetService,
		IsHostDiscovery:    scan.HostDiscovery,
		IsServiceDiscovery: scan.ServiceDiscovery,
		ScopeArg:           scan.ScopeArg,

		Started:  time.Time{},
		Finished: time.Time{},

		UserCommand:    make(chan string, 1),
		WorkerResponse: make(chan string, 1),
		ErrorChan:      make(chan error, 1),
		XMLPathsChan:   make(chan string, 1),
	}
}

func (wr *wranglerRepository) appendExclusions(args *[]string) {
	if project.ExcludeScopeFile != "" {
		*args = append(*args, "--exclude-file", project.ExcludeScopeFile)
	}
}

// StartWorkers runs the "primary" scans in batches read from `serviceEnum`.
// Now accepts an optional parent wait group to signal completion back to the caller
func (wr *wranglerRepository) startWorkers(project *models.Project, workers []models.Worker, targets []*models.Target, parentWg *sync.WaitGroup) {
	if targets == nil || len(targets) == 0 {
		log.Println("[!] Input channel is nil or empty")
		if parentWg != nil {
			// Decrement the wait counter even if no work was done
			for range workers {
				parentWg.Done()
			}
		}
		return
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		// When all work is done, signal to the parent wait group
		defer func() {
			if parentWg != nil {
				for range workers {
					parentWg.Done()
				}
			}
		}()

		taskId := uuidGen.UUIDv1().String()

		// Create a temporary directory for this batch
		tempDir, err := files.MakeTempDir(project.ProjectBase, project.TempPrefix)
		if err != nil {
			log.Printf("[!] Failed to create temp dir: %v", err)
			return
		}
		defer os.RemoveAll(tempDir)

		// Extract just the host IPs from targets
		hostIPs := make([]string, 0, len(targets))
		for _, target := range targets {
			hostIPs = append(hostIPs, target.Host)
		}

		// Write targets to temporary file
		tempFile := fmt.Sprintf("batch_%s.txt", taskId)
		batchFile, err := files.WriteSliceToFile(tempDir, tempFile, hostIPs)
		if err != nil {
			log.Printf("[!] Failed to write batch file: %v", err)
			return
		}

		log.Printf("[*] Created batch file %s with %d targets", batchFile, len(hostIPs))
		f := batchFile

		// Track which workers we'll actually run
		var activeWorkers []models.Worker
		var activeWorkerIndices []int

		// First, determine which workers should run
		for i := range workers {
			w := &workers[i]
			if determineAndAssignScanPorts(w, targets) {
				activeWorkers = append(activeWorkers, *w)
				activeWorkerIndices = append(activeWorkerIndices, i)
			} else {
				log.Printf("[*] Skipping worker: %s (no matching services in targets)", w.Description)
			}
		}

		var workerWg sync.WaitGroup
		log.Printf("[*] Starting %d of %d workers (skipped %d)",
			len(activeWorkers), len(workers), len(workers)-len(activeWorkers))

		for i := range activeWorkers {
			w := &activeWorkers[i]
			workerWg.Add(1)
			go func(w *models.Worker, localPath string) {
				defer workerWg.Done()

				args := append([]string{}, w.Args...)
				reportName := helpers.SpacesToUnderscores(taskId + "_" + w.Description)
				reportPath := path.Join(project.ReportDirParent, reportName)
				w.XMLReportPath = reportPath + ".xml"

				cmd := nmap.NewCommand("")
				cmd.Add().
					InputFile(localPath).
					OutputAll(reportPath)
				args = append(args, cmd.ToArgList()...)

				runWorker(w, args)
			}(w, f)
		}

		log.Printf("[*] Worker run initiated")
		workerWg.Wait()
		log.Printf("[*] Worker run completed")
	}()
	return
}

// determineAndAssignScanPorts configures ports for workers and returns false if the worker should be skipped
func determineAndAssignScanPorts(w *models.Worker, targets []*models.Target) bool {
	// Check if this is a worker with hardcoded ports
	if portsAreHardcoded(w) {
		// Even for hardcoded port workers, check if all targets have been processed
		allTargetsProcessed := true
		for _, target := range targets {
			if !workerTracker.IsTrackedForTarget(project.ExecutionID, target, w) {
				allTargetsProcessed = false
				break
			}
		}

		if allTargetsProcessed {
			log.Printf("[*] Skipping hardcoded port worker %s - all targets already processed", w.Description)
			return false
		}

		// Track these targets for this worker before running
		for _, target := range targets {
			workerTracker.TrackForTarget(project.ExecutionID, target, w)
		}
		return true
	}

	var udp []string
	var tcp []string

	// Keep track of which targets will actually be processed
	var targetsToProcess []*models.Target

	// If worker has targetService specified, filter ports by service
	if w.TargetService != nil && len(w.TargetService) > 0 {
		targetServiceStr := strings.Join(w.TargetService, ", ")

		// UUIDv1 unique ports while filtering out already processed targets
		var unprocessedTCPPorts []string
		var unprocessedUDPPorts []string

		for _, target := range targets {
			if workerTracker.IsTrackedForTarget(project.ExecutionID, target, w) {
				continue
			}

			targetsToProcess = append(targetsToProcess, target)

			// Extract TCP ports that match the service and haven't been processed
			for _, port := range target.Ports {
				if port.Protocol == nmap.TCP && serviceMatches(port.Service, w.TargetService) {
					if !workerTracker.IsTracked(project.ExecutionID, target.Host, port.PortID, port.Protocol, w) {
						unprocessedTCPPorts = append(unprocessedTCPPorts, port.PortID)
					}
				}
			}

			// Extract UDP ports that match the service and haven't been processed
			for _, port := range target.Ports {
				if port.Protocol == nmap.UDP && serviceMatches(port.Service, w.TargetService) {
					if !workerTracker.IsTracked(project.ExecutionID, target.Host, port.PortID, port.Protocol, w) {
						unprocessedUDPPorts = append(unprocessedUDPPorts, port.PortID)
					}
				}
			}
		}

		// Make the port lists unique
		tcpPorts := makeUniquePortList(unprocessedTCPPorts)
		udpPorts := makeUniquePortList(unprocessedUDPPorts)

		if (w.Protocol == nmap.TCP || w.Protocol == nmap.TCPandUDP) && len(tcpPorts) > 0 {
			t := nmap.TCPPortPrefix + strings.Join(tcpPorts, ",")
			tcp = []string{t}
		} else if w.Protocol == nmap.TCP || w.Protocol == nmap.TCPandUDP {
			log.Println("[!] No unprocessed TCP ports found for services: " + targetServiceStr)
		}

		if (w.Protocol == nmap.UDP || w.Protocol == nmap.TCPandUDP) && len(udpPorts) > 0 {
			u := nmap.UDPPortPrefix + strings.Join(udpPorts, ",")
			udp = []string{u}
		} else if w.Protocol == nmap.UDP || w.Protocol == nmap.TCPandUDP {
			log.Println("[!] No unprocessed UDP ports found for services: " + targetServiceStr)
		}

		// Skip worker if no unprocessed ports found for any protocol the worker handles
		if len(tcp) == 0 && len(udp) == 0 {
			log.Printf("[*] Skipping worker %s - no unprocessed matching services found: %s",
				w.Description, targetServiceStr)
			return false
		}
	} else {
		// For workers without a target service, check if all targets processed
		targetsToProcess = make([]*models.Target, 0, len(targets))
		for _, target := range targets {
			if !workerTracker.IsTrackedForTarget(project.ExecutionID, target, w) {
				targetsToProcess = append(targetsToProcess, target)
			}
		}

		if len(targetsToProcess) == 0 {
			log.Printf("[*] Skipping worker %s - all targets already processed", w.Description)
			return false
		}

		// Default implementation for workers without a target service
		tcpPorts := getUniquePortsForTargets(targetsToProcess, nmap.TCP)
		if (w.Protocol == nmap.TCP || w.Protocol == nmap.TCPandUDP) && (tcpPorts == nil || len(tcpPorts) == 0) {
			log.Println("[!] TCP ports nil or empty. setting all TCP ports")
			cmd := nmap.NewCommand("")
			cmd.Add().AllPorts()
			tcp = cmd.ToArgList()
		} else if w.Protocol == nmap.TCP || w.Protocol == nmap.TCPandUDP {
			t := nmap.TCPPortPrefix + strings.Join(tcpPorts, ",")
			tcp = []string{t}
		}

		udpPorts := getUniquePortsForTargets(targetsToProcess, nmap.UDP)
		if (w.Protocol == nmap.UDP || w.Protocol == nmap.TCPandUDP) && (udpPorts == nil || len(udpPorts) == 0) {
			fmt.Println("[!] UDP ports nil or empty. setting top 1000 UDP ports")
			cmd := nmap.NewCommand("")
			cmd.Add().TopPorts(1000)
			udp = cmd.ToArgList()
		} else if w.Protocol == nmap.UDP || w.Protocol == nmap.TCPandUDP {
			u := nmap.UDPPortPrefix + strings.Join(udpPorts, ",")
			udp = []string{u}
		}
	}

	for _, target := range targetsToProcess {
		workerTracker.TrackForTarget(project.ExecutionID, target, w)
	}

	appendPorts(tcp, udp, w)
	return true
}

// Helper function to make a slice of ports unique
func makeUniquePortList(ports []string) []string {
	uniquePorts := make(map[string]bool)
	for _, port := range ports {
		uniquePorts[port] = true
	}

	result := make([]string, 0, len(uniquePorts))
	for port := range uniquePorts {
		result = append(result, port)
	}
	return result
}

// New helper function to get unique ports for a specific service
func getUniquePortsForTargetsAndService(batch []*models.Target, protocol string, targetServices []string) []string {
	uniquePorts := make(map[string]bool)
	for _, host := range batch {
		for _, port := range host.Ports {
			if isValidPort(port.PortID) && port.Protocol == protocol && serviceMatches(port.Service, targetServices) {
				uniquePorts[port.PortID] = true
			}
		}
	}

	ports := make([]string, 0, len(uniquePorts))
	for key := range uniquePorts {
		ports = append(ports, key)
	}
	return ports
}

func portsAreHardcoded(worker *models.Worker) bool {
	for _, arg := range worker.Args {
		trimmedArg := strings.TrimSpace(arg)
		// Remove surrounding quotes if present
		if strings.HasPrefix(trimmedArg, "\"") && strings.HasSuffix(trimmedArg, "\"") {
			trimmedArg = trimmedArg[1 : len(trimmedArg)-1]
		}
		if strings.HasPrefix(trimmedArg, "-p") || trimmedArg == "-p-" || trimmedArg == "--top-ports" {
			return true
		}
	}
	return false
}

func appendPorts(tcp, udp []string, w *models.Worker) {
	if len(tcp) > 0 && len(udp) > 0 {
		// Check if already contains port flags
		if containsPortFlag(tcp) || containsPortFlag(udp) {
			// Add arguments directly without adding another -p
			w.Args = append(w.Args, tcp...)
			w.Args = append(w.Args, udp...)
		} else {
			t := strings.Join(tcp, ",")
			u := strings.Join(udp, ",")
			joined := strings.Join([]string{t, u}, ",")
			joined = "-p " + joined
			w.Args = append(w.Args, joined)
		}
	} else if len(tcp) > 0 && len(udp) == 0 {
		// Only TCP ports
		if containsPortFlag(tcp) {
			w.Args = append(w.Args, tcp...)
		} else {
			t := strings.Join(tcp, ",")
			t = "-p " + t
			w.Args = append(w.Args, t)
		}
	} else if len(udp) > 0 && len(tcp) == 0 {
		// Only UDP ports
		if containsPortFlag(udp) {
			w.Args = append(w.Args, udp...)
		} else {
			u := strings.Join(udp, ",")
			u = "-p " + u
			w.Args = append(w.Args, u)
		}
	}
}

// Helper function to check if args contain any port-related flags
func containsPortFlag(args []string) bool {
	for _, arg := range args {
		trimmed := strings.TrimSpace(arg)
		if strings.HasPrefix(trimmed, "-p") || trimmed == "--top-ports" {
			return true
		}
	}
	return false
}

func getUniquePortsForTargets(batch []*models.Target, protocol string) []string {
	uniquePorts := make(map[string]bool)
	for _, host := range batch {
		for _, port := range host.Ports {
			if isValidPort(port.PortID) && port.Protocol == protocol {
				uniquePorts[port.PortID] = true
			}
		}
	}

	ports := make([]string, 0, len(uniquePorts))
	for key := range uniquePorts {
		ports = append(ports, key)
	}
	return ports
}

func isValidPort(port string) bool {
	if matched, _ := regexp.MatchString(`^\d+$`, port); matched {
		return true
	}
	if matched, _ := regexp.MatchString(`^\d+-\d+$`, port); matched {
		return true
	}
	return false
}

// A simple wrapper for the actual worker logic
func runWorker(w *models.Worker, args []string) {
	log.Printf("[worker-%s] Starting with args: %v", w.Description, args)

	c := exec.Command(w.Tool, args...)
	output, err := c.CombinedOutput()

	if w.WorkerResponse != nil {
		log.Printf("[*] '%s' - Non-empty response detected [*]\n %s", w.Description, string(output))
		w.WorkerResponse <- string(output)
	}

	var xmlPath string
	for i, arg := range args {
		if arg == "-oA" && i+1 < len(args) {
			xmlPath = args[i+1] + ".xml"
			break
		}
	}
	if xmlPath != "" && w.XMLPathsChan != nil {
		if _, statErr := os.Stat(xmlPath); os.IsNotExist(statErr) {
			log.Printf("[worker-%s] XML file not found: %s", w.Description, xmlPath)
			if w.ErrorChan != nil {
				w.ErrorChan <- fmt.Errorf("XML file not generated: %s", xmlPath)
			}
		} else {
			w.XMLPathsChan <- xmlPath
		}
	}

	if w.ErrorChan != nil {
		w.ErrorChan <- err
	}
	log.Printf("[worker-%s] Completed", w.Description)
}

// runCommandCtx executes cmdName with args in its own process group and returns the cmd object, combined stdout/stderr, and error.
func runCommandCtx(ctx context.Context, worker *models.Worker, args []string) (cmd *exec.Cmd, stdout, stderr chan string, errs chan error, startErr error) {
	cmdName := worker.Tool
	cmd = exec.CommandContext(ctx, cmdName, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: 0}
	stdout = make(chan string, 1)
	stderr = make(chan string, 1)
	errs = make(chan error, 1)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return cmd, nil, nil, nil, fmt.Errorf("stdout pipe failed: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return cmd, nil, nil, nil, fmt.Errorf("stderr pipe failed: %w", err)
	}

	log.Printf("Starting %s with args %v for worker %s", cmdName, args, worker.ID.String())
	if startErr = cmd.Start(); startErr != nil {
		return cmd, nil, nil, nil, startErr
	}

	go func() {
		defer close(stdout)
		defer close(stderr)
		defer close(errs)

		var stdoutBuf, stderrBuf bytes.Buffer
		stdoutDone := make(chan struct{})
		stderrDone := make(chan struct{})

		go func() {
			io.Copy(&stdoutBuf, stdoutPipe)
			close(stdoutDone)
		}()

		go func() {
			io.Copy(&stderrBuf, stderrPipe)
			close(stderrDone)
		}()

		waitErr := cmd.Wait()
		<-stdoutDone
		<-stderrDone

		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() {
					log.Printf("worker-%s: %s terminated by signal %d", worker.ID, cmdName, status.Signal())
				}
			}
		}

		killProcessGroup(cmd, worker)

		stdout <- stdoutBuf.String()
		stderr <- stderrBuf.String()
		errs <- waitErr
	}()
	return cmd, stdout, stderr, errs, nil
}
