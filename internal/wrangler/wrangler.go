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
	fullScan         = make(chan string)
	sigCh            = make(chan os.Signal, 1)
	errCh            = make(chan error, 1)
	finalisedTargets = make([]string, 0) // used by discovery, updated in channels.go
	primaryWorkers   []Worker
)

// Project holds overall info, plus a slice of Workers we want to run.
type Project struct {
	ID               int
	Name             string `validate:"required"`
	InScopeFile      string `validate:"required"`
	ExcludeScopeFile string `validate:"required"`
	ReportDir        string `validate:"required"`
	Targets          []Target
	Workers          []Worker
}

type Target struct {
	Target    string `validate:"required"`
	OpenPorts []int
}

// Worker describes a single worker’s configuration and runtime state.
type Worker struct {
	ID          int
	Type        string
	Command     string
	Args        []string
	Target      string
	Description string

	// Start/finish times and optional timeout
	Started    time.Time
	Finished   time.Time
	Timeout    time.Duration
	CancelFunc context.CancelFunc

	// Channels for commands, optional responses, and errors
	UserCommand    chan string
	WorkerResponse chan string
	ErrorChan      chan error

	// Store the final output & error from the external command
	Output string
	Err    error

	// Store the exec.Cmd itself for SIGKILL if needed
	Cmd *exec.Cmd
}

// WranglerRepository defines the interface for creating/managing projects.
type WranglerRepository interface {
	NewProject() *Project
	ProjectInit(project *Project)
	setupInternal(project *Project)
	HostDiscoveryScan(workers []Worker, exclude string) *sync.WaitGroup
	StartWorkers(project *Project, fullScan <-chan string, batchSize int) *sync.WaitGroup
	DiscoveryWorkersInit(inScope []string, excludeFile string) *sync.WaitGroup
	CreateReportDirectory(dir, projectName string) (string, error)
	FlattenScopes(paths string) ([]string, error)
}

// wranglerRepository is our concrete implementation of the interface.
type wranglerRepository struct {
	cli models.CLI
}

// NewWranglerRepository constructs our repository and sets up signals.
func NewWranglerRepository(cli models.CLI) WranglerRepository {
	// Listen for SIGINT/SIGTERM so we can gracefully shut down
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

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
func (wr *wranglerRepository) NewProject() *Project {
	return &Project{
		Name:             wr.cli.ProjectName,
		ExcludeScopeFile: wr.cli.ScopeExclude,
		ReportDir:        wr.cli.Output,
	}
}

// ProjectInit initializes a Project. This example calls setupInternal() which can
// optionally run discovery, set up workers, etc.
func (wr *wranglerRepository) ProjectInit(project *Project) {
	wr.setupInternal(project)
	// If you wanted to do additional setup, you could do it here.
}

// setupInternal does the initial file setup, runs optional discovery, then
// starts the “primary” workers that read from `fullScan`.
func (wr *wranglerRepository) setupInternal(project *Project) {
	cwd, err := os.Getwd()
	if err != nil {
		log.Panic(err)
	}
	projectRoot = cwd
	nonRootUser = wr.cli.NonRootUser
	scopeDir = path.Join(cwd, scopeDir)

	// Create the report directory
	reportPath, err := wr.CreateReportDirectory(wr.cli.Output, wr.cli.ProjectName)
	if err != nil {
		fmt.Printf("Failed to create report directory: %v\n", err)
		return
	}

	// Load patterns from YAML
	args, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("Unable to load scans: %s", err.Error())
	}
	log.Printf("Loaded %d scans from YAML file", len(args))

	// Build "primaryWorkers" from YAML
	for i, pattern := range args {
		wk := Worker{
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

	// Flatten & write exclude file
	var excludeHosts []string
	if wr.cli.ScopeExclude != "" {
		excludeHosts, err = wr.FlattenScopes(wr.cli.ScopeExclude)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}
	}
	exclude, err := files.WriteSliceToFile(scopeDir, excludeFile, excludeHosts)

	// Always run CleanupPermissions() when the program exits
	defer func(reports, scopes string) {
		err := wr.CleanupPermissions(reports, scopes)
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

	// Possibly run discovery
	var discWg *sync.WaitGroup
	if wr.cli.RunDiscovery {
		// Run discovery; DiscoveryResponseMonitor will close(fullScan)
		discWg = wr.DiscoveryWorkersInit(inScope, exclude)
	} else {
		// If no discovery, just write user-supplied scope & then close channel
		inScopeFile, err = files.WriteSliceToFile(scopeDir, inScopeFile, inScope)
		if err != nil {
			fmt.Printf("Failed to write in-scope file: %v\n", err)
			return
		}
		close(fullScan)
	}

	// Finalize the project
	project.InScopeFile = inScopeFile
	project.ExcludeScopeFile = wr.cli.ScopeExclude
	project.ReportDir = reportPath
	project.Workers = primaryWorkers

	// Start the primary workers
	wg := wr.StartWorkers(project, fullScan, batchSize)

	// Setup signal handling & error watchers
	wr.SetupSignalHandler(project.Workers, sigCh)
	wr.DrainWorkerErrors(project.Workers, errCh)
	wr.ListenToWorkerErrors(project.Workers, errCh)

	// If we used discovery, wait for it to fully finish.
	if discWg != nil {
		discWg.Wait()
		log.Println("All discovery workers have finished.")
	}

	// Wait for primary workers to finish
	wg.Wait()
	log.Println("All primary workers have stopped.")

	// Debug info if desired
	if wr.cli.DebugWorkers {
		for i := range project.Workers {
			w := &project.Workers[i]
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
}

// HostDiscoveryScan spawns an Nmap -sn job per host. Returns a WaitGroup.
func (wr *wranglerRepository) HostDiscoveryScan(workers []Worker, exclude string) *sync.WaitGroup {
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

		go func(dw *Worker) {
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
			cmdObj, output, err := runCommandCtx(ctx, dw.Command, dw.Args)
			dw.Cmd = cmdObj
			dw.WorkerResponse <- output
			if err != nil {
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

// StartWorkers runs the "primary" scans in batches read from `fullScan`.
func (wr *wranglerRepository) StartWorkers(p *Project, fullScan <-chan string, size int) *sync.WaitGroup {
	var wg sync.WaitGroup
	var bid int

	if fullScan == nil {
		// No channel => no discovered hosts => do nothing
		return &wg
	}

	for {
		batch := helpers.ReadNTargetsFromChannel(fullScan, size)
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
func worker(wk *Worker, args []string, wg *sync.WaitGroup) {
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

		cmdObj, output, err := runCommandCtx(ctx, wk.Command, args)
		wk.Cmd = cmdObj
		wk.Output = output
		wk.Err = err

		// This worker runs just once, so close the channel & exit
		close(wk.UserCommand)
		wk.Finished = time.Now()
		return
	}
}

// runCommandCtx executes cmdName with args in its own process group
// and returns the cmd object, combined stdout/stderr, and error.
func runCommandCtx(ctx context.Context, cmdName string, args []string) (*exec.Cmd, string, error) {
	cmd := exec.CommandContext(ctx, cmdName, args...)

	// Put the child in its own process group
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		return cmd, "", err
	}
	waitErr := cmd.Wait()

	return cmd, out.String(), waitErr
}
