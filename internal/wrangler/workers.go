package wrangler

import (
	"Wrangler/internal/files"
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
		for batch := range helpers.ReadNTargetsFromChannelContinuous(inChan, batchSize) {
			if len(batch) == 0 {
				continue
			}

			ports := getUniquePortsForTargets(batch)
			var portStr string
			if ports == nil || len(ports) == 0 {
				fmt.Println("[!] batch ports is nil or empty. setting all ports")
				portStr = "0-65535"

			} else {
				portStr = strings.Join(ports, ",")
			}

			prefix := fmt.Sprintf("batch_%d_", batchID)
			f, err := files.WriteSliceToFile(scopeDir, prefix+inScopeFile, hostsFromBatch(batch))
			if err != nil {
				log.Printf("[!] Failed to write targets to file: %v", err)
				continue
			}
			batchID++

			for i := range workers {
				custPorts := portStr
				w := &workers[i]
				wg.Add(1)
				go func(w *models.Worker, localPath string) {
					defer wg.Done()

					args := append([]string{}, w.Args...)
					args = append(args, "-iL", localPath)
					if project.ExcludeScopeFile != "" {
						args = append(args, "--excludefile", project.ExcludeScopeFile)
					}

					if !portsAreHardcoded(w) {
						args = append(args, []string{"-p ", custPorts}...)
					}

					reportName := helpers.SpacesToUnderscores(prefix + w.Description)
					reportPath := path.Join(project.ReportDirParent, reportName)
					args = append(args, "-oA", reportPath)
					w.XMLReportPath = reportPath + ".xml"

					runWorker(w, args)
				}(w, f)
			}
		}
		log.Println("[*] Worker run complete...")
	}()
	return &wg
}

func portsAreHardcoded(worker *models.Worker) bool {
	for _, arg := range worker.Args {
		if arg == "-p" || arg == "-p-" {
			return true
		}
	}
	return false
}

func getUniquePortsForTargets(batch []models.Target) []string {
	// Create a map[string]bool to track unique ports
	uniquePorts := make(map[string]bool)
	for _, host := range batch {
		p := host.Ports
		for _, port := range p {
			if ok := uniquePorts[port]; !ok {
				uniquePorts[port] = true
			}
		}
	}

	// Convert map keys to []string
	ports := make([]string, len(uniquePorts))
	var index int
	for key := range uniquePorts {
		ports[index] = key
		index++
	}
	return ports
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

	// TODO: Check this. ErrorChan is never not nil, its an instance of a chan
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

		stdout <- stdoutBuf.String()
		stderr <- stderrBuf.String()
		errs <- waitErr
	}()

	return cmd, stdout, stderr, errs, nil
}
