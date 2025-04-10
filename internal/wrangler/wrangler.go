package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/models"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"strings"
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
	batchSize   = 200

	// Channels & global vars
	sigCh = make(chan os.Signal, 1)
	errCh = make(chan error, 1)
)

// WranglerRepository defines the interface for creating/managing projects.
type WranglerRepository interface {
	NewProject() *models.Project
	ProjectInit(project *models.Project)
	setupInternal(project *models.Project)
	DiscoveryScan(workers []models.Worker, exclude string) *sync.WaitGroup
	startWorkers(project *models.Project, workers []models.Worker, inChan <-chan models.Target, batchSize int) *sync.WaitGroup
	DiscoveryWorkersInit(inScope []string, excludeFile string, scopeDir string, project *models.Project) (*sync.WaitGroup, chan struct{})
	CreateReportDirectory(dir, projectName string) (string, error)
	FlattenScopes(paths string) ([]string, error)
	startScanProcess(project *models.Project, inScope []string, exclude string)
	PrimaryScanners(project *models.Project) *sync.WaitGroup
}

// wranglerRepository is our concrete implementation of the interface.
type wranglerRepository struct {
	cli         models.CLI
	serviceEnum chan models.Target
	fullScan    chan models.Target
}

// NewWranglerRepository constructs our repository and sets up signals.
func NewWranglerRepository(cli models.CLI) WranglerRepository {
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGINT)
	return &wranglerRepository{
		cli:         cli,
		serviceEnum: make(chan models.Target, batchSize),
		fullScan:    make(chan models.Target, batchSize),
	}
}

// NewProject creates a new Project (not yet started).
func (wr *wranglerRepository) NewProject() *models.Project {

	project := &models.Project{
		Name:             wr.cli.ProjectName,
		ExcludeScopeFile: wr.cli.ScopeExclude,
		ReportDirParent:  wr.cli.Output,
		TempDir:          ".temp-",
	}

	if wr.cli.BatchSize > 0 {
		fmt.Printf("Nmap batch size set to: %d\n", wr.cli.BatchSize)
		batchSize = wr.cli.BatchSize
	}

	nonRootUser = wr.cli.NonRootUser

	cwd, err := os.Getwd()
	if err != nil {
		log.Panic(err)
	}

	project.ProjectBase = cwd
	scopeDir = path.Join(cwd, scopeDir)

	reportDirectory, err := wr.CreateReportDirectory(wr.cli.Output, wr.cli.ProjectName)
	if err != nil {
		fmt.Printf("[!] Failed to create report directory: %v\n", err)
		return nil
	}
	project.ReportDirParent = reportDirectory
	project.ProjectReportPath = path.Join(project.ReportDirParent, project.Name)

	project.InScopeFile = path.Join(cwd, scopeDir, inScopeFile)
	project.ExcludeScopeFile = wr.cli.ScopeExclude

	return project
}

func (wr *wranglerRepository) ProjectInit(project *models.Project) {
	wr.setupInternal(project)
}

// setupInternal does the initial file setup, runs optional discovery, then
// starts the “primary” workers that read from `serviceEnum`.
func (wr *wranglerRepository) setupInternal(project *models.Project) {
	// Flatten & write scope exclusion
	var excludeHosts []string
	var exclude string
	var err error
	if wr.cli.ScopeExclude != "" {
		excludeHosts, err = wr.FlattenScopes(wr.cli.ScopeExclude)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}
		exclude, err = files.WriteSliceToFile(scopeDir, excludeFile, excludeHosts)
	}

	// Always run when the program exits
	defer func() {
		entries, err := os.ReadDir(project.ProjectBase)
		if err != nil {
			fmt.Printf("[!] unable to list directory: %s. Error: %s", project.ProjectBase, err)
		}
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), project.TempDir) {
				err = os.RemoveAll(entry.Name())
				if err != nil {
					fmt.Printf("[!] failed to delete temp directory: %s. Error: %s", entry.Name(), err)
				}
			}
		}
	}()

	// Flatten user-supplied scope
	var inScope []string
	if wr.cli.ScopeFiles != "" {
		inScope, err = wr.FlattenScopes(wr.cli.ScopeFiles)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}
	}

	if len(inScope) > batchSize {
		wr.fullScan = make(chan models.Target, len(inScope))
		wr.serviceEnum = make(chan models.Target, len(inScope))
	}

	wr.startScanProcess(project, inScope, exclude)
}
