package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/internal/nmap"
	"Wrangler/pkg/helpers"
	"Wrangler/pkg/models"
	"bytes"
	"context"
	"fmt"
	"github.com/google/uuid"
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

// NewWorker creates a new worker with automatically generated ID and initialized channels
func NewWorker(command string, args []string, protocol, description string) models.Worker {
	return models.Worker{
		ID:          uuid.Must(uuid.NewUUID()),
		Command:     command,
		Args:        args,
		Protocol:    protocol,
		Description: description,

		Started:  time.Time{},
		Finished: time.Time{},

		UserCommand:    make(chan string, 1),
		WorkerResponse: make(chan string, 1),
		ErrorChan:      make(chan error, 1),
		XMLPathsChan:   make(chan string, 1),
	}
}

// StartWorkers runs the "primary" scans in batches read from `serviceEnum`.
func (wr *wranglerRepository) startWorkers(project *models.Project, workers []models.Worker, targets []*models.Target) {
	if targets == nil || len(targets) == 0 {
		log.Println("[!] Input channel is nil or empty")
		return
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		taskId := uuid.Must(uuid.NewUUID()).String()

		f, err := files.WriteSliceToFile(scopeDir, taskId+inScopeFile, extractHostIPs(targets))
		if err != nil {
			log.Printf("[!] Failed to write targets to file: %v", err)
			return
		}

		var workerWg sync.WaitGroup // Separate waitgroup for workers
		log.Printf("[*] Starting %d workers", len(workers))
		for i := range workers {
			w := &workers[i]
			determineAndAssignScanPorts(w, targets)
			workerWg.Add(1)
			go func(w *models.Worker, localPath string) {
				defer workerWg.Done()

				args := append([]string{}, w.Args...)
				reportName := helpers.SpacesToUnderscores(taskId + w.Description)
				reportPath := path.Join(project.ReportDirParent, reportName)
				w.XMLReportPath = reportPath + ".xml"

				cmd := nmap.NewCommand("", "", nil)
				cmd.Add().
					InputFile(localPath).
					OutputAll(reportPath)
				args = append(args, cmd.ToArgList()...)

				if project.ExcludeScopeFile != "" {
					cmd.Add().ExcludeFile(project.ExcludeScopeFile)
				}
				runWorker(w, args)
			}(w, f)
		}
		log.Printf("[*] Worker %s run initiated", taskId)
		workerWg.Wait()
		log.Printf("[*] Worker %s completed", taskId)
	}()
	return
}

// determineAndAssignScanPorts configures port scanning settings for a worker based on target batch requirements.
//
// The function determines which TCP and/or UDP ports a worker should scan based on the worker's
// configured protocol (TCP, UDP, or both) and the ports specified in the target batch. If no ports
// are specified for a protocol that the worker is configured to use, default port settings are applied:
// - For TCP: All ports are set to be scanned
// - For UDP: Top 1000 most common ports are set to be scanned
//
// If ports are already hardcoded in the worker configuration, the function returns without making changes.
//
// Parameters:
//   - w: Pointer to a worker model containing protocol configuration and where port settings will be stored
//   - batch: Slice of target models from which to extract unique port specifications
//
// The function handles four main cases:
//  1. TCP ports required but none specified in targets
//  2. TCP ports specified and worker configured for TCP scanning
//  3. UDP ports required but none specified in targets
//  4. UDP ports specified and worker configured for UDP scanning
//
// Port settings are formatted according to nmap command requirements and stored in the worker model.
func determineAndAssignScanPorts(w *models.Worker, targets []*models.Target) {
	if portsAreHardcoded(w) {
		return
	}

	var udp []string
	var tcp []string

	tcpPorts := getUniquePortsForTargets(targets, nmap.TCP)
	if (w.Protocol == nmap.TCP || w.Protocol == nmap.TCPandUDP) && (tcpPorts == nil || len(tcpPorts) == 0) {
		fmt.Println("[!] TCP ports nil or empty. setting all TCP ports")
		cmd := nmap.NewCommand("", "", nil)
		cmd.Add().AllPorts()
		tcp = cmd.ToArgList()
	} else if w.Protocol == nmap.TCP || w.Protocol == nmap.TCPandUDP {
		t := "T:" + strings.Join(tcpPorts, ",")
		tcp = []string{t}
		appendPorts(tcp, udp, w)
	}

	udpPorts := getUniquePortsForTargets(targets, nmap.UDP)
	if (w.Protocol == nmap.UDP || w.Protocol == nmap.TCPandUDP) && (udpPorts == nil || len(udpPorts) == 0) {
		fmt.Println("[!] UDP ports nil or empty. setting top 1000 UDP ports")
		cmd := nmap.NewCommand("", "", nil)
		cmd.Add().TopPorts(1000)
		udp = cmd.ToArgList()
	} else if w.Protocol == nmap.UDP || w.Protocol == nmap.TCPandUDP {
		u := "U:" + strings.Join(udpPorts, ",")
		udp = []string{u}
		appendPorts(tcp, udp, w)
	}
}

func portsAreHardcoded(worker *models.Worker) bool {
	for _, arg := range worker.Args {
		if strings.HasPrefix(arg, "-p") || arg == "-p-" || arg == "--top-ports" {
			return true
		}
	}
	return false
}

func appendPorts(tcp, udp []string, w *models.Worker) {
	if len(tcp) > 0 && len(udp) > 0 {
		t := strings.Join(tcp, ",")
		u := strings.Join(udp, ",")
		joined := strings.Join([]string{t, u}, ",")
		joined = "-p " + joined
		w.Args = append(w.Args, joined)

	} else if len(tcp) > 0 && len(udp) == 0 {
		t := strings.Join(tcp, ",")
		t = "-p " + t
		w.Args = append(w.Args, t)

	} else if len(udp) > 0 && len(tcp) == 0 {
		u := strings.Join(udp, ",")
		u = "-p " + u
		w.Args = append(w.Args, u)
	}
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

	c := exec.Command(w.Command, args...)
	output, err := c.CombinedOutput()

	if w.WorkerResponse != nil {
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
			log.Printf("[worker-%s] Sent XML path: %s", w.Description, xmlPath)
		}
	}

	if w.ErrorChan != nil {
		w.ErrorChan <- err
	}
	log.Printf("[worker-%s] Completed", w.Description)
}

// Utility function to extract just the host IPs
func extractHostIPs(batch []*models.Target) []string {
	var list []string
	for _, b := range batch {
		list = append(list, b.Host)
	}
	return list
}

// runCommandCtx executes cmdName with args in its own process group and returns the cmd object, combined stdout/stderr, and error.
func runCommandCtx(ctx context.Context, worker *models.Worker, args []string) (cmd *exec.Cmd, stdout, stderr chan string, errs chan error, startErr error) {
	cmdName := worker.Command
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

	log.Printf("Starting %s with args %v for worker %d", cmdName, args, worker.ID)
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
