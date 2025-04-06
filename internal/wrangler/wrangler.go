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

	// Flatten and write exclude file
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
		err := wr.CleanupPermissions(reports, scopes) // see channels.go
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
		discWg = wr.DiscoveryWorkersInit(inScope, exclude)
		go func() {
			discWg.Wait()
			log.Println("All discovery workers done.")
			close(fullScan) // signals no more discovered hosts
		}()
	} else {
		// If no discovery, just write user-supplied in-scope to file & close channel
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

	// Wait for primary workers to finish
	wg.Wait()
	log.Println("All primary workers have stopped.")

	// Inspect each worker’s output & error
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
			dw.Started = time.Now()

			for {
				cmd, ok := <-dw.UserCommand
				if !ok {
					dw.Finished = time.Now()
					return
				}
				if cmd == WorkerStop {
					if dw.CancelFunc != nil {
						dw.CancelFunc()
					}
					dw.Finished = time.Now()
					return
				}

				// normal run
				ctx, cancel := context.WithCancel(context.Background())
				dw.CancelFunc = cancel

				output, err := runCommandCtx(ctx, dw.Command, dw.Args)
				dw.WorkerResponse <- output // let DiscoveryResponseMonitor parse it

				if err != nil {
					dw.ErrorChan <- err
				} else {
					dw.ErrorChan <- nil
				}
			}
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

			w.Args = append(w.Args, "-T4", "-iL", f)
			if p.ExcludeScopeFile != "" {
				w.Args = append(w.Args, "--excludefile", p.ExcludeScopeFile)
			}

			reportName := helpers.SpacesToUnderscores(prefix + "_" + w.Description)
			reportPath := path.Join(p.ReportDir, reportName)
			w.Args = append(w.Args, "-oA", reportPath)

			go worker(w, &wg)

			// Send "run" => the worker will do exactly one run, then exit
			w.UserCommand <- "run"
			//close(w.UserCommand)
		}
	}
	return &wg
}

// worker reads from UserCommand, runs an external command once, stores output.
func worker(wk *Worker, wg *sync.WaitGroup) {
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
			if wk.CancelFunc != nil {
				wk.CancelFunc()
			}
			wk.Finished = time.Now()
			return
		}

		// Normal "run"
		ctx, cancel := context.WithCancel(context.Background())
		wk.CancelFunc = cancel

		output, err := runCommandCtx(ctx, wk.Command, wk.Args)
		wk.Output = output
		wk.Err = err

		// This worker runs just once, so close the channel & return
		close(wk.UserCommand)
		wk.Finished = time.Now()
		return
	}
}

// runCommandCtx executes cmdName with args and returns combined stdout/stderr.
func runCommandCtx(ctx context.Context, cmdName string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, cmdName, args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	return out.String(), err
}
