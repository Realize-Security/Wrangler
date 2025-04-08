package wrangler

import (
	"Wrangler/pkg/models"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
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

	log.Printf("[startWorkers] Starting %d workers", len(workers))
	go func() {
		for t := range inChan {
			log.Printf("[startWorkers] Received target %s with ports %v", t.Host, t.Ports)
			wg.Add(len(workers))
			for i := range workers {
				w := &workers[i]
				// Append the target host to the args
				targetArgs := append(w.Args, t.Host)
				w.UserCommand <- "run"
				go worker(w, targetArgs, &wg)
			}
		}
		log.Println("[startWorkers] Input channel closed")
	}()
	return &wg
}

//func (wr *wranglerRepository) startWorkers(project *models.Project, inChan <-chan models.Target, batchSize int) *sync.WaitGroup {
//	var wg sync.WaitGroup
//	workers := project.Workers
//	if len(workers) == 0 {
//		log.Println("[startWorkers] No workers defined")
//		go func() {
//			for t := range inChan {
//				log.Printf("[startWorkers] Draining target %s with ports %v", t.Host, t.Ports)
//			}
//		}()
//		return &wg
//	}
//
//	log.Printf("[startWorkers] Starting %d workers", len(workers))
//	go func() {
//		for t := range inChan {
//			log.Printf("[startWorkers] Received target %s with ports %v", t.Host, t.Ports)
//			wg.Add(len(workers))
//			for i := range workers {
//				w := &workers[i]
//				go worker(w, w.Args, &wg)
//			}
//		}
//		log.Println("[startWorkers] Input channel closed")
//	}()
//	return &wg
//}

//func (wr *wranglerRepository) startWorkers(p *models.Project, ch <-chan models.Target, size int) *sync.WaitGroup {
//	var wg sync.WaitGroup
//	var bid int
//
//	if ch == nil {
//		return &wg
//	}
//
//	for {
//		batch := helpers.ReadNTargetsFromChannel(ch, size)
//		if len(batch) == 0 {
//			break
//		}
//
//		prefix := "batch_" + strconv.Itoa(bid) + "_"
//		write := make([]string, 0)
//		for _, target := range batch {
//			write = append(write, target.Host)
//		}
//		f, err := files.WriteSliceToFile(scopeDir, prefix+inScopeFile, write)
//		if err != nil {
//			panic("unable to create file")
//		}
//		bid++
//
//		for i := range p.Workers {
//			wg.Add(1)
//			w := &p.Workers[i]
//
//			// Make a copy of original w.Args so we don't keep appending
//			localArgs := append([]string{}, w.Args...)
//			localArgs = append(localArgs, "-T4", "-iL", f)
//			if p.ExcludeScopeFile != "" {
//				localArgs = append(localArgs, "--excludefile", p.ExcludeScopeFile)
//			}
//
//			reportName := helpers.SpacesToUnderscores(prefix + w.Description)
//			reportPath := path.Join(p.ReportDir, reportName)
//			localArgs = append(localArgs, "-oA", reportPath)
//			w.XMLReportPath = reportPath + ".xml"
//
//			go worker(w, localArgs, &wg)
//
//			// Trigger the worker to run exactly once
//			w.UserCommand <- "run"
//		}
//	}
//	return &wg
//}

// worker reads from UserCommand, runs an external command once, stores output.
func worker(wk *models.Worker, args []string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("[Worker %d] WaitGroup Done", wk.ID)
	}()
	wk.Started = time.Now()

	log.Printf("[Worker %d] Starting with args: %v", wk.ID, args)

	for {
		cmd, ok := <-wk.UserCommand
		if !ok {
			log.Printf("[Worker %d] UserCommand closed", wk.ID)
			wk.Finished = time.Now()
			return
		}
		if cmd == WorkerStop {
			log.Printf("[Worker %d] Received STOP command", wk.ID)
			if wk.CancelFunc != nil {
				wk.CancelFunc()
			}
			if wk.Cmd != nil && wk.Cmd.Process != nil {
				_ = syscall.Kill(-wk.Cmd.Process.Pid, syscall.SIGKILL)
			}
			wk.Finished = time.Now()
			return
		}

		log.Printf("[Worker %d] Running command", wk.ID)
		ctx, cancel := context.WithCancel(context.Background())
		wk.CancelFunc = cancel

		cmdObj, outChan, stderrChan, errChan, startErr := runCommandCtx(ctx, wk, args)
		wk.Cmd = cmdObj

		if startErr != nil {
			log.Printf("[Worker %d] Command start failed: %v", wk.ID, startErr)
			wk.Err = startErr
			wk.Output = ""
			wk.StdError = ""
			wk.ErrorChan <- startErr
			if wk.XMLPathsChan != nil {
				close(wk.XMLPathsChan)
			}
			wk.Finished = time.Now()
			close(wk.UserCommand)
			return
		}

		wk.Output = <-outChan
		wk.StdError = <-stderrChan
		wk.Err = <-errChan

		log.Printf("[Worker %d] Command completed. Output: %d bytes, Stderr: %s, Err: %v", wk.ID, len(wk.Output), wk.StdError, wk.Err)

		log.Printf("[Worker %d] Post-command: Preparing to send response", wk.ID)
		if wk.WorkerResponse != nil {
			wk.WorkerResponse <- wk.Output
			log.Printf("[Worker %d] Sent response to WorkerResponse", wk.ID)
		}

		log.Printf("[Worker %d] XMLReportPath set to: %s", wk.ID, wk.XMLReportPath)
		if wk.XMLReportPath != "" && wk.Err == nil {
			if _, err := os.Stat(wk.XMLReportPath); os.IsNotExist(err) {
				log.Printf("[Worker %d] XML file not found: %s", wk.ID, wk.XMLReportPath)
				wk.ErrorChan <- fmt.Errorf("XML file not generated: %s", wk.XMLReportPath)
			} else {
				log.Printf("[Worker %d] Sending XML path: %s", wk.ID, wk.XMLReportPath)
				wk.XMLPathsChan <- wk.XMLReportPath
			}
		} else {
			log.Printf("[Worker %d] Skipping XML path (XMLReportPath: %s, Err: %v)", wk.ID, wk.XMLReportPath, wk.Err)
		}

		log.Printf("[Worker %d] Post-XML: Sending error if any", wk.ID)
		if wk.ErrorChan != nil {
			wk.ErrorChan <- wk.Err
			log.Printf("[Worker %d] Sent error to ErrorChan", wk.ID)
		}

		log.Printf("[Worker %d] Closing XMLPathsChan", wk.ID)
		if wk.XMLPathsChan != nil {
			close(wk.XMLPathsChan)
			log.Printf("[Worker %d] Closed XMLPathsChan", wk.ID)
		}

		wk.Finished = time.Now()
		log.Printf("[Worker %d] Finishing worker", wk.ID)
		close(wk.UserCommand)
		log.Printf("[Worker %d] Closed UserCommand", wk.ID)
		return
	}
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
