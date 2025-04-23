package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/models"
	"Wrangler/pkg/serializers"
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
	scopeDir    = "discovered_scope"
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
	DiscoveryScan(workers []models.Worker, exclude string, wg *sync.WaitGroup)
	startWorkers(project *models.Project, workers []models.Worker, inChan <-chan models.Target, batchSize int) *sync.WaitGroup
	DiscoveryWorkersInit(inScope []string, excludeFile string, scopeDir string, project *models.Project) *sync.WaitGroup
	CreateReportDirectory(dir, projectName string) (string, error)
	FlattenScopes(paths string) ([]string, error)
	startScanProcess(project *models.Project, inScope []string, exclude string)
	PrimaryScanners(project *models.Project, workers []models.Worker) *sync.WaitGroup
	GetServiceEnumBroadcast() *TypedBroadcastChannel[models.Target]
	GetFullScanBroadcast() *TypedBroadcastChannel[models.Target]
}

// wranglerRepository is our concrete implementation of the interface.
type wranglerRepository struct {
	cli             models.CLI
	serviceEnum     chan models.Target
	fullScan        chan models.Target
	serviceEnumBC   *TypedBroadcastChannel[models.Target]
	fullScanBC      *TypedBroadcastChannel[models.Target]
	staticWorkers   []models.Worker
	templateWorkers []models.Worker
}

// NewWranglerRepository constructs our repository and sets up signals.
func NewWranglerRepository(cli models.CLI) WranglerRepository {
	// Source channels for incoming targets
	serviceEnumSource := make(chan models.Target, batchSize)
	fullScanSource := make(chan models.Target, batchSize)

	// Main pipeline channels
	serviceEnumMain := make(chan models.Target, batchSize)
	fullScanMain := make(chan models.Target, batchSize)

	// Broadcast channels
	serviceEnumBroadcast := make(chan models.Target, batchSize)
	fullScanBroadcast := make(chan models.Target, batchSize)

	// tee goroutines
	go teeTargets(serviceEnumSource, serviceEnumMain, serviceEnumBroadcast)
	go teeTargets(fullScanSource, fullScanMain, fullScanBroadcast)

	// Signal handling (unchanged)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGINT)

	// Return the repository with all channels
	return &wranglerRepository{
		cli:           cli,
		serviceEnum:   serviceEnumMain,
		fullScan:      fullScanMain,
		serviceEnumBC: NewTypedBroadcastChannel[models.Target](serviceEnumBroadcast),
		fullScanBC:    NewTypedBroadcastChannel[models.Target](fullScanBroadcast),
	}
}
func teeTargets(in <-chan models.Target, out1, out2 chan<- models.Target) {
	for t := range in {
		out1 <- t
		out2 <- t
	}
}

// GetServiceEnumBroadcast returns the broadcast channel for service enumeration
func (wr *wranglerRepository) GetServiceEnumBroadcast() *TypedBroadcastChannel[models.Target] {
	return wr.serviceEnumBC
}

// GetFullScanBroadcast returns the broadcast channel for full scan
func (wr *wranglerRepository) GetFullScanBroadcast() *TypedBroadcastChannel[models.Target] {
	return wr.fullScanBC
}

// NewProject creates a new Project (not yet started).
func (wr *wranglerRepository) NewProject() *models.Project {

	project := &models.Project{
		Name:             wr.cli.ProjectName,
		ExcludeScopeFile: wr.cli.ScopeExclude,
		ReportDirParent:  wr.cli.Output,
		TempPrefix:       ".temp",
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
	scopeDir = path.Join(cwd, scopeDir+"-"+project.Name)
	project.TempPrefix = project.TempPrefix + "-" + project.Name

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
			if entry.IsDir() && strings.HasPrefix(entry.Name(), project.TempPrefix) {
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

	wr.loadWorkers()
	wr.startScanProcess(project, inScope, exclude)
}

func (wr *wranglerRepository) loadWorkers() {
	static := make([]models.Worker, 0)
	templated := make([]models.Worker, 0)
	scans, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("[!] Unable to load scans: %s", err)
		panic(err.Error())
	}

	log.Printf("[*] Loaded %d scans from YAML", len(scans))

	var workers []models.Worker
	for i, pattern := range scans {
		w := models.Worker{
			ID:             i,
			Type:           pattern.Tool,
			Command:        pattern.Tool,
			Args:           pattern.Args,
			Protocol:       pattern.Protocol,
			Description:    pattern.Description,
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string, 1),
			ErrorChan:      make(chan error, 1),
			XMLPathsChan:   make(chan string, 1),
		}
		workers = append(workers, w)
	}

	for _, worker := range workers {
		if portsAreHardcoded(&worker) {
			static = append(static, worker)
		} else {
			templated = append(templated, worker)
		}
	}

	wr.staticWorkers = static
	wr.templateWorkers = templated

	log.Printf("[*] Loaded %d static workers", len(static))
	log.Printf("[*] Loaded %d templated workers", len(templated))
}
