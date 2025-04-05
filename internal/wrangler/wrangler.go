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
	"sync"
	"syscall"
	"time"
)

// workerStop is the command used to tell the worker goroutine to exit.
const WorkerStop = "STOP"

var (
	scopeDir    = "./assessment_scope/"
	inScopeFile = "in_scope.txt"
	excludeFile = "out_of_scope.txt"
	nonRootUser = ""
	projectRoot = ""
	batchSize   = 200
)

// Set up channels & listeners needed by all workflows
var (
	fullScan         = make(chan string)
	sigCh            = make(chan os.Signal, 1)
	errCh            = make(chan error, 1)
	finalisedTargets = make([]string, 0)
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

type defaultProtoCols struct {
	TCP string
	UDP string
}

// Worker describes a single worker’s configuration and runtime state.
type Worker struct {
	ID             int
	Type           string `validate:"required"`
	Command        string `validate:"required"`
	Args           []string
	Target         string
	Description    string `validate:"required"`
	Started        time.Time
	Finished       time.Time
	Timeout        time.Duration
	CancelFunc     context.CancelFunc
	UserCommand    chan string
	WorkerResponse chan string
	ErrorChan      chan error
}

// WranglerRepository defines the interface for creating and managing Projects.
type WranglerRepository interface {
	NewProject() *Project
	ProjectInit(project *Project)
	setupInternal(project *Project)
	HostDiscoveryScan(workers []Worker, exclude string) *sync.WaitGroup
	StartWorkers(project *Project, fullScan <-chan string, batchSize int) *sync.WaitGroup
	DiscoveryWorkersInit(inScope []string, excludeFile string) *sync.WaitGroup
	DiscoveryResponseMonitor(workers []Worker, unknownHosts, fullScan chan<- string)
	CleanupPermissions(reports, scopes string) error
	WorkerTimeout(workers []Worker)
	SetupSignalHandler(workers []Worker, sigCh <-chan os.Signal)
	DrainWorkerErrors(workers []Worker, errCh chan<- error)
	ListenToWorkerErrors(workers []Worker, errCh <-chan error)
	CreateReportDirectory(dir, projectName string) (string, error)
	FlattenScopes(paths string) ([]string, error)
}

type wranglerRepository struct {
	cli models.CLI
}

// NewWranglerRepository constructs our repository.
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
		fmt.Printf("Nmap batch size set to: %d", cli.BatchSize)
		batchSize = cli.BatchSize
	}
	return &wranglerRepository{
		cli: cli,
	}
}

// NewProject creates a new Project (not yet started).
func (wr *wranglerRepository) NewProject() *Project {
	return &Project{
		Name:             wr.cli.ProjectName,
		ExcludeScopeFile: wr.cli.ScopeExclude,
		ReportDir:        wr.cli.Output,
	}
}

// ProjectInit initializes each Worker’s channels but does NOT start them yet.
func (wr *wranglerRepository) ProjectInit(project *Project) {
	wr.setupInternal(project)
	for i, wk := range project.Workers {
		wk.UserCommand = make(chan string)
		wk.WorkerResponse = make(chan string)
		project.Workers[i] = wk
	}
}

func (wr *wranglerRepository) setupInternal(project *Project) {
	cwd, err := os.Getwd()
	if err != nil {
		log.Panic(err)
	}
	projectRoot = cwd
	nonRootUser = wr.cli.NonRootUser

	reportPath, err := wr.CreateReportDirectory(wr.cli.Output, wr.cli.ProjectName)
	if err != nil {
		fmt.Printf(err.Error())
		return
	}

	args, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("unable to load scans: %s", err.Error())
		// Decide whether to return or keep going based on your preference
	}
	log.Printf("Loaded %d scans from YAML file", len(args))

	//Initialise primary primaryWorkers
	//var primaryWorkers []Worker
	for i, pattern := range args {
		worker := Worker{
			ID:             i,
			Type:           pattern.Tool,
			Command:        pattern.Tool,
			Args:           pattern.Args,
			Description:    pattern.Description,
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string),
			ErrorChan:      make(chan error),
		}
		primaryWorkers = append(primaryWorkers, worker)
	}

	// First flatten and write out of scope hosts to file
	// Leave in-scope files until host discovery avoided or completed
	var excludeHosts []string
	if wr.cli.ScopeExclude != "" {
		excludeHosts, err = wr.FlattenScopes(wr.cli.ScopeExclude)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}
	}
	exclude, err := files.WriteSliceToFile(cwd, scopeDir, excludeFile, excludeHosts)

	// Initialise CleanupPermissions() to always run when program exits
	defer func(reports, scopes string) {
		err := wr.CleanupPermissions(reports, scopes)
		if err != nil {
			log.Printf("Error during CleanupPermissions(): %v", err)
		}
	}(reportPath, scopeDir)

	// If discovery is run, this will create a list of hosts to be added to scope.
	// Otherwise, use user-supplied list verbatim

	// First get user-supplied scope
	var inScope []string
	if wr.cli.ScopeFiles != "" {
		inScope, err = wr.FlattenScopes(wr.cli.ScopeFiles)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}
	}

	var discWg *sync.WaitGroup
	if wr.cli.RunDiscovery {
		discWg = wr.DiscoveryWorkersInit(inScope, exclude)
		go func() {
			discWg.Wait()
			log.Println("All discovery workers done.")
			close(fullScan)
		}()
	} else {
		// If no discovery, write scope to file straight away
		inScopeFile, err = files.WriteSliceToFile(cwd, scopeDir, inScopeFile, inScope)
		close(fullScan)
	}

	project.InScopeFile = inScopeFile
	project.Workers = primaryWorkers
	project.ReportDir = reportPath

	wg := wr.StartWorkers(project, fullScan, batchSize)

	wr.SetupSignalHandler(project.Workers, sigCh)
	wr.DrainWorkerErrors(project.Workers, errCh)
	wr.ListenToWorkerErrors(project.Workers, errCh)

	// 4. Wait until all primary workers finish
	wg.Wait()
	log.Println("All primaryWorkers have stopped. Exiting now.")
}

// HostDiscoveryScan initiates ICMP and port check discovery.
// This runs one nmap scan per host:
// nmap -sn -PS22,80,443,3389 -PA80,443 -PU40125 -PY80,443 -PE -PP -PM -T4 -v --discovery-ignore-rst 192.168.1.1
func (wr *wranglerRepository) HostDiscoveryScan(workers []Worker, exclude string) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		w := &workers[i]
		w.Command = "nmap"
		if exclude != "" {
			w.Args = append(w.Args, "--excludefile")
			w.Args = append(w.Args, exclude)
		}
		// Only initialize if not set
		if w.UserCommand == nil {
			w.UserCommand = make(chan string, 1)
		}
		if w.WorkerResponse == nil {
			w.WorkerResponse = make(chan string)
		}
		if w.ErrorChan == nil {
			w.ErrorChan = make(chan error)
		}
		go worker(w, &wg)
		w.UserCommand <- "run"
	}
	return &wg
}

// StartWorkers spins up all workers in goroutines. Each worker listens for commands
// on its UserCommand channel and sends results on its WorkerResponse channel.
func (wr *wranglerRepository) StartWorkers(p *Project, fullScan <-chan string, size int) *sync.WaitGroup {
	var wg sync.WaitGroup
	allConfirmed := make([]string, 0)

	for {
		batch := helpers.ReadNTargetsFromChannel(fullScan, size)
		if len(batch) == 0 {
			break
		}
		allConfirmed = append(allConfirmed, batch...)

		for i := range p.Workers {
			wg.Add(1)
			w := &p.Workers[i]
			// Add additional tool arguments
			w.Args = append(w.Args, "-T4")

			w.Args = append(w.Args, "-iL")
			w.Args = append(w.Args, p.InScopeFile)

			if p.ExcludeScopeFile != "" {
				w.Args = append(w.Args, "--excludefile")
				w.Args = append(w.Args, p.ExcludeScopeFile)
			}

			reportName := helpers.SpacesToUnderscores(w.Description)
			workerReport := path.Join(p.ReportDir, reportName)
			w.Args = append(w.Args, "-oA")
			w.Args = append(w.Args, workerReport)

			go worker(w, &wg)
			w.UserCommand <- "run"
		}
	}
	return &wg
}

// worker continuously reads from worker.UserCommand, runs the external command
// (or does other long-running tasks), and sends results back on worker.WorkerResponse.
func worker(wk *Worker, wg *sync.WaitGroup) {
	defer wg.Done()
	wk.Started = time.Now()

	for {
		cmd, ok := <-wk.UserCommand
		if !ok {
			wk.Finished = time.Now()
			wk.WorkerResponse <- fmt.Sprintf("Worker %d: commands channel closed, stopping.", wk.ID)
			return
		}

		if cmd == WorkerStop {
			if wk.CancelFunc != nil {
				wk.CancelFunc()
			}
			wk.Finished = time.Now()
			wk.WorkerResponse <- fmt.Sprintf("Worker %d: STOP command received, shutting down.", wk.ID)
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		wk.CancelFunc = cancel

		output, err := runCommandCtx(ctx, wk.Command, wk.Args)
		wk.WorkerResponse <- output

		if err != nil {
			wk.ErrorChan <- err
		} else {
			wk.ErrorChan <- nil
		}
		close(wk.ErrorChan)
	}
}

// runCommandCtx is a helper to execute an external command with the given args
// and return combined stdout/stderr.
func runCommandCtx(ctx context.Context, cmdName string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, cmdName, args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	return out.String(), err
}
