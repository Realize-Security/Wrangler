package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/helpers"
	"Wrangler/pkg/models"
	"Wrangler/pkg/serializers"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// workerStop is the command used to tell the worker goroutine to exit.
const WorkerStop = "STOP"

var (
	scopeDir    = "assessment_scope"
	inScopeFile = "in_scope.txt"
	excludeFile = "out_of_scope.txt"
	nonRootUser = ""
	projectRoot = ""
	batchSize   = 200

	// Channels & global vars
	serviceEnum    = make(chan string)
	fullScan       = make(chan string)
	sigCh          = make(chan os.Signal, 1)
	errCh          = make(chan error, 1)
	primaryWorkers []models.Worker
)

// WranglerRepository defines the interface for creating/managing projects.
type WranglerRepository interface {
	NewProject() *models.Project
	ProjectInit(project *models.Project)
	setupInternal(project *models.Project)
	HostDiscoveryScan(workers []models.Worker, exclude string) *sync.WaitGroup
	startWorkers(project *models.Project, fullScan <-chan string, batchSize int) *sync.WaitGroup
	DiscoveryWorkersInit(inScope []string, excludeFile string) *sync.WaitGroup
	CreateReportDirectory(dir, projectName string) (string, error)
	FlattenScopes(paths string) ([]string, error)
	startScanProcess(project *models.Project, inScope []string, exclude string)
	PrimaryScanners(project *models.Project, discWg *sync.WaitGroup)
}

// wranglerRepository is our concrete implementation of the interface.
type wranglerRepository struct {
	cli models.CLI
}

// NewWranglerRepository constructs our repository and sets up signals.
func NewWranglerRepository(cli models.CLI) WranglerRepository {
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGINT)

	args, err := serializers.LoadScansFromYAML(cli.PatternFile)
	if err != nil {
		log.Printf("unable to load scans: %s", err.Error())
		os.Exit(1)
	}
	log.Printf("Loaded %d scans from YAML file", len(args))

	cwd, err := os.Getwd()
	if err != nil {
		log.Panic(err)
	}
	projectRoot = cwd
	nonRootUser = cli.NonRootUser

	if cli.BatchSize > 0 {
		fmt.Printf("Nmap batch size set to: %d\n", cli.BatchSize)
		batchSize = cli.BatchSize
	}

	return &wranglerRepository{cli: cli}
}

// NewProject creates a new Project (not yet started).
func (wr *wranglerRepository) NewProject() *models.Project {
	return &models.Project{
		Name:             wr.cli.ProjectName,
		ExcludeScopeFile: wr.cli.ScopeExclude,
		ReportDir:        wr.cli.Output,
	}
}

// ProjectInit initializes a Project. This example calls setupInternal() which can
// optionally run discovery, set up workers, etc.
func (wr *wranglerRepository) ProjectInit(project *models.Project) {
	wr.setupInternal(project)
	// If you wanted to do additional setup, you could do it here.
}

// setupInternal does the initial file setup, runs optional discovery, then
// starts the “primary” workers that read from `serviceEnum`.
func (wr *wranglerRepository) setupInternal(project *models.Project) {
	cwd, err := os.Getwd()
	if err != nil {
		log.Panic(err)
	}
	project.Cwd = cwd
	//projectRoot = cwd
	nonRootUser = wr.cli.NonRootUser
	scopeDir = path.Join(cwd, scopeDir)
	project.ReportPath = path.Join(cwd, project.ReportDir)

	// Create the report directory
	reportPath, err := wr.CreateReportDirectory(wr.cli.Output, wr.cli.ProjectName)
	if err != nil {
		fmt.Printf("Failed to create report directory: %v\n", err)
		return
	}

	// Moved patterns from here

	// Flatten & write exclude file
	var excludeHosts []string
	var exclude string
	if wr.cli.ScopeExclude != "" {
		excludeHosts, err = wr.FlattenScopes(wr.cli.ScopeExclude)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}
		exclude, err = files.WriteSliceToFile(scopeDir, excludeFile, excludeHosts)
	}

	// Always run CleanupPermissions() when the program exits
	defer func(reports, scopes string) {
		err = wr.CleanupPermissions(reports, scopes)
		if err != nil {
			log.Printf("Error during CleanupPermissions(): %v", err)
		}
	}(reportPath, scopeDir)

	// Flatten user-supplied scope
	var inScope []string
	if wr.cli.ScopeFiles != "" {
		inScope, err = wr.FlattenScopes(wr.cli.ScopeFiles)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}
	}
	wr.startScanProcess(project, inScope, exclude)

}

func (wr *wranglerRepository) startScanProcess(project *models.Project, inScope []string, exclude string) {
	// Possibly run discovery
	var discWg *sync.WaitGroup
	var inScopeFile string
	var err error
	if wr.cli.RunDiscovery {
		// Run discovery; DiscoveryResponseMonitor will close(serviceEnum)
		discWg = wr.DiscoveryWorkersInit(inScope, exclude)
	} else {
		// If no discovery, just write user-supplied scope & then close channel
		inScopeFile, err = files.WriteSliceToFile(scopeDir, inScopeFile, inScope)
		if err != nil {
			fmt.Printf("Failed to write in-scope file: %v\n", err)
			return
		}
		close(serviceEnum)
	}

	// Finalize the project
	project.InScopeFile = path.Join(project.Cwd, scopeDir, inScopeFile)
	project.ExcludeScopeFile = wr.cli.ScopeExclude
	project.ReportDir = project.ReportPath
	//project.Workers = primaryWorkers

	enumWg := wr.ServiceEnumeration(project, discWg)
	wr.PrimaryScanners(project, enumWg)
}

// HostDiscoveryScan spawns an Nmap -sn job per host. Returns a WaitGroup.
func (wr *wranglerRepository) HostDiscoveryScan(workers []models.Worker, exclude string) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		w := &workers[i]
		w.Command = "nmap"
		if exclude != "" {
			w.Args = append(w.Args, "--excludefile", exclude)
		}
		if w.UserCommand == nil {
			w.UserCommand = make(chan string, 1)
		}
		if w.WorkerResponse == nil {
			w.WorkerResponse = make(chan string)
		}
		if w.ErrorChan == nil {
			w.ErrorChan = make(chan error)
		}

		go func(dw *models.Worker) {
			defer wg.Done()
			defer close(dw.WorkerResponse) // Closes when goroutine exits
			dw.Started = time.Now()

			cmd, ok := <-dw.UserCommand
			if !ok {
				dw.Finished = time.Now()
				return
			}
			if cmd == WorkerStop {
				if dw.CancelFunc != nil {
					dw.CancelFunc()
				}
				if dw.Cmd != nil && dw.Cmd.Process != nil {
					_ = syscall.Kill(-dw.Cmd.Process.Pid, syscall.SIGKILL)
				}
				dw.Finished = time.Now()
				return
			}

			// Normal "run" (runs once)
			ctx, cancel := context.WithCancel(context.Background())
			dw.CancelFunc = cancel
			cmdObj, outStr, errStr, err := runCommandCtx(ctx, dw.Command, dw.Args)
			dw.Cmd = cmdObj

			dw.WorkerResponse <- outStr

			// If the command failed, store stderr text in dw.StdError.
			if err != nil {
				if errStr != "" {
					fmt.Println(errStr)
					dw.StdError = errStr
				}
				dw.ErrorChan <- err
			} else {
				dw.ErrorChan <- nil
			}
			dw.Finished = time.Now()
		}(w)

		w.UserCommand <- "run"
	}
	return &wg
}

func (wr *wranglerRepository) ServiceEnumeration(project *models.Project, discWg *sync.WaitGroup) *sync.WaitGroup {
	w := models.Worker{
		ID:             1,
		Type:           "nmap",
		Command:        "nmap",
		Description:    "HostService enumeration scans on all ports",
		UserCommand:    make(chan string, 1),
		WorkerResponse: make(chan string),
		ErrorChan:      make(chan error),
	}
	args := []string{"-sTV", "-p-"}
	w.Args = append(w.Args, args...)
	project.Workers = []models.Worker{w}

	// Start the primary workers
	wg := wr.startWorkers(project, serviceEnum, batchSize)

	// Setup signal handling & error watchers
	wr.SetupSignalHandler(project.Workers, sigCh)
	wr.DrainWorkerErrors(project.Workers, errCh)
	wr.ListenToWorkerErrors(project.Workers, errCh)

	if discWg != nil {
		discWg.Wait()
		log.Println("All discovery workers have finished.")
	}

	wg.Wait()
	log.Println("HostService enumeration workers have stopped.")

	// Debug info if desired
	if wr.cli.DebugWorkers {
		debugWorkers(project.Workers)
	}
	return wg
}

func (wr *wranglerRepository) PrimaryScanners(project *models.Project, enumWg *sync.WaitGroup) {
	// Load patterns from YAML
	args, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("Unable to load scans: %s", err.Error())
		enumWg.Done()
		return
	}
	log.Printf("Loaded %d scans from YAML file", len(args))

	// Build "primaryWorkers" from YAML
	for i, pattern := range args {
		wk := models.Worker{
			ID:             i,
			Type:           pattern.Tool,
			Command:        pattern.Tool,
			Args:           pattern.Args,
			Description:    pattern.Description,
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string),
			ErrorChan:      make(chan error),
		}
		primaryWorkers = append(primaryWorkers, wk)
	}

	project.Workers = primaryWorkers
	// Start the primary workers
	wg := wr.startWorkers(project, fullScan, batchSize)

	// Setup signal handling & error watchers
	wr.SetupSignalHandler(project.Workers, sigCh)
	wr.DrainWorkerErrors(project.Workers, errCh)
	wr.ListenToWorkerErrors(project.Workers, errCh)

	// If we used discovery, wait for it to fully finish.
	if enumWg != nil {
		enumWg.Wait()
	}

	wg.Wait()
	log.Println("All primary scanners have stopped.")

	// Debug info if desired
	if wr.cli.DebugWorkers {
		debugWorkers(project.Workers)
	}
}

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
			// channel closed => done
			wk.Finished = time.Now()
			return
		}
		if cmd == WorkerStop {
			// Forced shutdown
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

		cmdObj, outStr, errStr, err := runCommandCtx(ctx, wk.Command, args)
		wk.Cmd = cmdObj
		wk.Output = outStr
		wk.StdError = errStr
		wk.Err = err

		// This worker runs just once, so close the channel & exit
		close(wk.UserCommand)
		wk.Finished = time.Now()
		return
	}
}

// runCommandCtx executes cmdName with args in its own process group
// and returns the cmd object, combined stdout/stderr, and error.
func runCommandCtx(ctx context.Context, cmdName string, args []string) (cmd *exec.Cmd, stdout string, stderr string, err error) {

	cmd = exec.CommandContext(ctx, cmdName, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: 0}

	// Separate buffers for stdout and stderr
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return cmd, "", "", err
	}
	waitErr := cmd.Wait()

	return cmd, stdoutBuf.String(), stderrBuf.String(), waitErr
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
