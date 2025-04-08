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
	"os/exec"
	"path"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// StartWorkers runs the "primary" scans in batches read from `serviceEnum`.
func (wr *wranglerRepository) startWorkers(p *models.Project, ch <-chan models.Target, size int) *sync.WaitGroup {
	var wg sync.WaitGroup
	var bid int

	if ch == nil {
		return &wg
	}

	for {
		batch := helpers.ReadNTargetsFromChannel(ch, size)
		if len(batch) == 0 {
			break
		}

		prefix := "batch_" + strconv.Itoa(bid) + "_"
		write := make([]string, 0)
		for _, target := range batch {
			write = append(write, target.Host)
		}
		f, err := files.WriteSliceToFile(scopeDir, prefix+inScopeFile, write)
		if err != nil {
			panic("unable to create file")
		}
		bid++

		for i := range p.Workers {
			wg.Add(1)
			w := &p.Workers[i]

			// Make a copy of original w.Args so we don't keep appending
			localArgs := append([]string{}, w.Args...)
			localArgs = append(localArgs, "-T4", "-iL", f)
			if p.ExcludeScopeFile != "" {
				localArgs = append(localArgs, "--excludefile", p.ExcludeScopeFile)
			}

			reportName := helpers.SpacesToUnderscores(prefix + w.Description)
			reportPath := path.Join(p.ReportDir, reportName)
			localArgs = append(localArgs, "-oA", reportPath)
			w.XMLReportPath = reportPath + ".xml"

			go worker(w, localArgs, &wg)

			// Trigger the worker to run exactly once
			w.UserCommand <- "run"
		}
	}
	return &wg
}

// worker reads from UserCommand, runs an external command once, stores output.
func worker(wk *models.Worker, args []string, wg *sync.WaitGroup) {
	defer wg.Done()
	wk.Started = time.Now()

	for {
		cmd, ok := <-wk.UserCommand
		if !ok {
			wk.Finished = time.Now()
			return
		}
		if cmd == WorkerStop {
			if wk.CancelFunc != nil {
				wk.CancelFunc()
			}
			if wk.Cmd != nil && wk.Cmd.Process != nil {
				_ = syscall.Kill(-wk.Cmd.Process.Pid, syscall.SIGKILL)
			}
			wk.Finished = time.Now()
			return
		}

		// Normal "run" => do it once
		ctx, cancel := context.WithCancel(context.Background())
		wk.CancelFunc = cancel

		cmdObj, outChan, stderrChan, errChan, startErr := runCommandCtx(ctx, wk, args)
		wk.Cmd = cmdObj

		if startErr != nil {
			wk.Err = startErr
			wk.Output = ""
			wk.StdError = ""
			close(wk.UserCommand)
			wk.Finished = time.Now()
			return
		}

		go func() {
			wk.Output = <-outChan
			wk.StdError = <-stderrChan
			wk.Err = <-errChan

			if wk.WorkerResponse != nil {
				wk.WorkerResponse <- wk.Output
			}

			if wk.XMLReportPath != "" {
				wk.XMLPathsChan <- wk.XMLReportPath
			}

			if wk.ErrorChan != nil {
				wk.ErrorChan <- wk.Err
				fmt.Printf("error: %s", wk.Err)
			}

			wk.Finished = time.Now()
		}()

		// Since this worker runs once, close the channel and exit
		close(wk.UserCommand)
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
