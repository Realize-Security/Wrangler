package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/helpers"
	"Wrangler/pkg/models"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// StartWorkers runs the "primary" scans in batches read from `serviceEnum`.
func (wr *wranglerRepository) startWorkers(p *models.Project, ch <-chan string, size int) *sync.WaitGroup {
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
		f, err := files.WriteSliceToFile(scopeDir, prefix+inScopeFile, batch)
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

		cmdObj, outChan, stderrChan, errChan, startErr := runCommandCtx(ctx, wk.Command, args)
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
			if wk.ErrorChan != nil {
				wk.ErrorChan <- wk.Err
			}

			wk.Finished = time.Now()
		}()

		// Since this worker runs once, close the channel and exit
		close(wk.UserCommand)
		return // Exit the loop after starting the command
	}
}

// runCommandCtx executes cmdName with args in its own process group
// and returns the cmd object, combined stdout/stderr, and error.
func runCommandCtx(ctx context.Context, cmdName string, args []string) (cmd *exec.Cmd, stdoutChan, stderrChan chan string, errChan chan error, startErr error) {
	cmd = exec.CommandContext(ctx, cmdName, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: 0}

	// Channels to receive stdout, stderr, and errors
	stdoutChan = make(chan string, 1)
	stderrChan = make(chan string, 1)
	errChan = make(chan error, 1)

	// Separate buffers for stdout and stderr
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Start the command
	if startErr = cmd.Start(); startErr != nil {
		return cmd, nil, nil, nil, startErr
	}

	// Run the command in a goroutine
	go func() {
		defer close(stdoutChan)
		defer close(stderrChan)
		defer close(errChan)

		// Wait for the command to complete
		waitErr := cmd.Wait()

		// Send the results to the channels
		stdoutChan <- stdoutBuf.String()
		stderrChan <- stderrBuf.String()
		errChan <- waitErr
	}()

	return cmd, stdoutChan, stderrChan, errChan, nil
}

func debugWorkers(workers []models.Worker) {
	for i := range workers {
		w := &workers[i]
		fmt.Printf("\n=== Worker %d (%s) ===\n", w.ID, w.Description)
		fmt.Println("Stdout/Stderr:")
		fmt.Println(w.Output)
		if w.Err != nil {
			fmt.Printf("Error: %v\n", w.Err)
		} else {
			fmt.Println("Error: <nil>")
		}
	}
}
