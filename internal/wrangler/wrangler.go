package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/models"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"
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
	DiscoveryScan(workers []models.Worker, exclude string) *sync.WaitGroup
	startWorkers(project *models.Project, fullScan <-chan string, batchSize int) *sync.WaitGroup
	DiscoveryWorkersInit(inScope []string, excludeFile string) *sync.WaitGroup
	CreateReportDirectory(dir, projectName string) (string, error)
	FlattenScopes(paths string) ([]string, error)
	startScanProcess(project *models.Project, inScope []string, exclude string)
	PrimaryScanners(project *models.Project, enumWg *sync.WaitGroup) *sync.WaitGroup
}

// wranglerRepository is our concrete implementation of the interface.
type wranglerRepository struct {
	cli models.CLI
}

// NewWranglerRepository constructs our repository and sets up signals.
func NewWranglerRepository(cli models.CLI) WranglerRepository {
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGINT)

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
	nonRootUser = wr.cli.NonRootUser
	scopeDir = path.Join(cwd, scopeDir)
	project.ReportPath = path.Join(cwd, project.ReportDir)

	// Finalize the project
	project.InScopeFile = path.Join(project.Cwd, scopeDir, inScopeFile)
	project.ExcludeScopeFile = wr.cli.ScopeExclude
	project.ReportDir = project.ReportPath

	// Create the report directory
	reportPath, err := wr.CreateReportDirectory(wr.cli.Output, wr.cli.ProjectName)
	if err != nil {
		fmt.Printf("Failed to create report directory: %v\n", err)
		return
	}

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
