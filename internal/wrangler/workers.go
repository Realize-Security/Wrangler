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
	"strconv"
	"sync"
	"syscall"
)

// StartWorkers runs the "primary" scans in batches read from `serviceEnum`.
func (wr *wranglerRepository) startWorkers(project *models.Project, inChan <-chan models.Target, batchSize int) *sync.WaitGroup {
	var wg sync.WaitGroup
	workers := project.Workers
	if len(workers) == 0 {
		log.Println("[startWorkers] No workers defined")
		go func() {
			for t := range inChan {
				log.Printf("[startWorkers] Draining target %s with ports %v", t.Host, t.Ports)
			}
		}()
		return &wg
	}

	if inChan == nil {
		log.Println("[startWorkers] Input channel is nil")
		return &wg
	}

	log.Printf("[startWorkers] Starting %d workers", len(workers))
	wg.Add(1) // For the goroutine
	go func() {
		defer wg.Done()
		defer log.Println("[startWorkers] Input channel closed")
		var bid int
		for batch := range helpers.ReadNTargetsFromChannelContinuous(inChan, batchSize) {
			if len(batch) == 0 {
				continue
			}

			prefix := "batch_" + strconv.Itoa(bid) + "_"
			write := make([]string, 0, len(batch))
			for _, target := range batch {
				log.Printf("[startWorkers] Received target %s with ports %v", target.Host, target.Ports)
				write = append(write, target.Host)
			}

			f, err := files.WriteSliceToFile(scopeDir, prefix+"in_scope.txt", write)
			if err != nil {
				log.Printf("[startWorkers] Failed to write targets to file: %v", err)
				continue
			}
			bid++

			for i := range workers {
				wg.Add(1)
				w := &workers[i]

				localArgs := append([]string{}, w.Args...)
				localArgs = append(localArgs, "-T4", "-iL", f)
				if project.ExcludeScopeFile != "" {
					localArgs = append(localArgs, "--excludefile", project.ExcludeScopeFile)
				}

				reportName := helpers.SpacesToUnderscores(prefix + w.Description)
				reportPath := path.Join(project.ReportDirParent, reportName)
				localArgs = append(localArgs, "-oA", reportPath)
				w.XMLReportPath = reportPath + ".xml"

				go worker(w, localArgs, &wg)
				w.UserCommand <- "run"
			}
		}
	}()
	return &wg
}

func worker(w *models.Worker, args []string, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Printf("[Worker %s] Starting with args: %v", w.Description, args)

	// Execute the scan command
	c := exec.Command(w.Command, args...)
	output, err := c.CombinedOutput()
	log.Printf("[Worker %s] Captured %d bytes of stdout", w.Description, len(output))

	// Send output to WorkerResponse channel
	if w.WorkerResponse != nil {
		w.WorkerResponse <- string(output)
		log.Printf("[Worker %s] Sent %d bytes to WorkerResponse", w.Description, len(output))
	}

	// Extract and send XML report path (if applicable)
	var xmlPath string
	for i, arg := range args {
		if arg == "-oA" && i+1 < len(args) {
			xmlPath = args[i+1] + ".xml"
			break
		}
	}
	if xmlPath != "" && w.XMLPathsChan != nil {
		if _, err := os.Stat(xmlPath); os.IsNotExist(err) {
			log.Printf("[Worker %s] XML file not found: %s", w.Description, xmlPath)
			if w.ErrorChan != nil {
				w.ErrorChan <- fmt.Errorf("XML file not generated: %s", xmlPath)
			}
		} else {
			w.XMLPathsChan <- xmlPath
			log.Printf("[Worker %s] Sent XML path: %s", w.Description, xmlPath)
		}
	}

	// Send error (or nil) to ErrorChan
	if w.ErrorChan != nil {
		w.ErrorChan <- err
		log.Printf("[Worker %s] Sent error to ErrorChan", w.Description)
	}

	log.Printf("[Worker %s] Worker finished", w.Description)
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
			log.Printf("Worker %d: Captured %d bytes of stdout", worker.ID, stdoutBuf.Len())
			close(stdoutDone)
		}()

		go func() {
			io.Copy(&stderrBuf, stderrPipe)
			log.Printf("Worker %d: Captured %d bytes of stderr", worker.ID, stderrBuf.Len())
			close(stderrDone)
		}()

		waitErr := cmd.Wait()
		<-stdoutDone
		<-stderrDone

		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() {
					log.Printf("Worker %d: %s terminated by signal %d", worker.ID, cmdName, status.Signal())
				}
			}
		}

		stdout <- stdoutBuf.String()
		stderr <- stderrBuf.String()
		errs <- waitErr
	}()

	return cmd, stdout, stderr, errs, nil
}
