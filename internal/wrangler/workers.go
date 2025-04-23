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
)

// StartWorkers runs the "primary" scans in batches read from `serviceEnum`.
func (wr *wranglerRepository) startWorkers(
	project *models.Project,
	workers []models.Worker,
	inChan <-chan models.Target,
	batchSize int,
) *sync.WaitGroup {
	var wg sync.WaitGroup
	if len(workers) == 0 {
		// Drain any incoming targets so we don't block upstream
		go func() {
			for t := range inChan {
				log.Printf("[!]  No workers defined. Draining target %s with ports %v", t.Host, t.Ports)
			}
		}()
		return &wg
	}

	if inChan == nil {
		log.Println("[!] Input channel is nil")
		return &wg
	}

	log.Printf("[*] Starting %d workers", len(workers))

	wg.Add(1)

	go func() {
		defer wg.Done()

		var batchID int
		for batch := range helpers.ReadTargetsFromChannel(inChan, batchSize) {
			if len(batch) == 0 {
				continue
			}

			prefix := fmt.Sprintf("batch_%d_", batchID)
			f, err := files.WriteSliceToFile(scopeDir, prefix+inScopeFile, hostsFromBatch(batch))
			if err != nil {
				log.Printf("[!] Failed to write targets to file: %v", err)
				continue
			}
			batchID++

			for i := range workers {
				w := &workers[i]
				definePorts(w, batch)
				wg.Add(1)
				go func(w *models.Worker, localPath string) {
					defer wg.Done()

					args := append([]string{}, w.Args...)
					reportName := helpers.SpacesToUnderscores(prefix + w.Description)
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
		}
		log.Println("[*] Worker run complete...")
	}()
	return &wg
}

func definePorts(w *models.Worker, batch []models.Target) {
	if portsAreHardcoded(w) {
		return
	}

	tcpPorts := getUniquePortsForTargets(batch, nmap.TCP)
	var tcp []string
	if (w.Protocol == nmap.TCP || w.Protocol == nmap.TCPandUDP) && (tcpPorts == nil || len(tcpPorts) == 0) {
		fmt.Println("[!] TCP ports nil or empty. setting all TCP ports")
		tcp = []string{"-p-"}
	} else {
		tcp = []string{strings.Join(tcpPorts, ",")}
	}

	udpPorts := getUniquePortsForTargets(batch, nmap.UDP)
	var udp []string
	if (w.Protocol == nmap.UDP || w.Protocol == nmap.TCPandUDP) && (udpPorts == nil || len(udpPorts) == 0) {
		fmt.Println("[!] UDP ports nil or empty. setting top 1000 UDP ports")
		cmd := nmap.NewCommand("", "", nil)
		cmd.Add().TopPorts(1000)
		udp = cmd.ToArgList()
	} else {
		tcp = []string{strings.Join(udpPorts, ",")}
	}

	if len(tcp) > 0 {
		w.Args = append(w.Args, tcp...)
	}

	if len(udp) > 0 {
		w.Args = append(w.Args, udp...)
	}
}

func portsAreHardcoded(worker *models.Worker) bool {
	for _, arg := range worker.Args {
		if arg == "-p" || arg == "-p-" || arg == "--top-ports" {
			return true
		}
	}
	return false
}

func getUniquePortsForTargets(batch []models.Target, protocol string) []string {
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
		log.Printf("[worker-%s] Sent %d bytes to WorkerResponse", w.Description, len(output))
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
		log.Printf("[worker-%s] Sent error to ErrorChan", w.Description)
	}

	log.Printf("[worker-%s] Worker finished", w.Description)
}

// Utility function to extract just the host IPs
func hostsFromBatch(batch []models.Target) []string {
	var list []string
	for _, b := range batch {
		list = append(list, b.Host)
	}
	return list
}

// runCommandCtx executes cmdName with args in its own process group
// and returns the cmd object, combined stdout/stderr, and error.
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

		// Stream stdout
		go func() {
			io.Copy(&stdoutBuf, stdoutPipe)
			log.Printf("worker-%d: Captured %d bytes of stdout", worker.ID, stdoutBuf.Len())
			close(stdoutDone)
		}()

		go func() {
			io.Copy(&stderrBuf, stderrPipe)
			log.Printf("worker-%d: Captured %d bytes of stderr", worker.ID, stderrBuf.Len())
			close(stderrDone)
		}()

		waitErr := cmd.Wait()
		<-stdoutDone
		<-stderrDone

		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() {
					log.Printf("worker-%d: %s terminated by signal %d", worker.ID, cmdName, status.Signal())
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
