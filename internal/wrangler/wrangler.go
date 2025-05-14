package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/concurrency"
	"Wrangler/pkg/models"
	"Wrangler/pkg/serializers"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
)

// WorkerStop is the command used to tell the worker goroutine to exit.
const WorkerStop = "STOP"

var (
	// Atomics
	discoveryDone   atomic.Bool
	serviceEnumDone atomic.Bool

	scopeDir    = "discovered_scope"
	inScopeFile = "in_scope.txt"
	excludeFile = "out_of_scope.txt"
	batchSize   = 200

	// Channels
	sigCh = make(chan os.Signal, 1)
	errCh = make(chan error, 1)
)

// WranglerRepository defines the interface for creating/managing projects.
type WranglerRepository interface {
	NewProject() *models.Project
	ProjectInit(project *models.Project)
	setupInternal(project *models.Project)
	DiscoveryScan(workers []models.Worker, exclude string, wg *sync.WaitGroup)
	startWorkers(project *models.Project, workers []models.Worker, targets []*models.Target)
	DiscoveryWorkersInit(inScope []string, excludeFile string, scopeDir string, project *models.Project)
	CreateReportDirectory(dir, projectName string) (string, error)
	FlattenScopes(paths string) ([]string, error)
	startScanProcess(project *models.Project, inScope []string, exclude string)
	TemplateScanners(project *models.Project, workers []models.Worker)
}

// wranglerRepository is our concrete implementation of the interface.
type wranglerRepository struct {
	cli             models.CLI
	serviceEnum     *concurrency.Registry[models.Target]
	staticWorkers   *concurrency.Registry[models.Worker]
	staticTargets   *concurrency.Registry[models.Target]
	templateWorkers *concurrency.Registry[models.Worker]
	templateTargets *concurrency.Registry[models.Target]
}

// NewWranglerRepository constructs our repository and sets up signals.
func NewWranglerRepository(cli models.CLI) WranglerRepository {
	return &wranglerRepository{
		cli:             cli,
		serviceEnum:     concurrency.NewRegistry[models.Target](TargetEquals),
		staticWorkers:   concurrency.NewRegistry[models.Worker](WorkerEquals),
		staticTargets:   concurrency.NewRegistry[models.Target](TargetEquals),
		templateWorkers: concurrency.NewRegistry[models.Worker](WorkerEquals),
		templateTargets: concurrency.NewRegistry[models.Target](TargetEquals),
	}
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
	for _, s := range scans {
		w := NewWorker(s.Tool, s.Args, s.Protocol, s.Description)
		workers = append(workers, w)
	}

	for _, worker := range workers {
		if portsAreHardcoded(&worker) {
			static = append(static, worker)
		} else {
			templated = append(templated, worker)
		}
	}

	wr.staticWorkers.AddAll(static)
	log.Printf("[*] Loaded %d static workers", len(static))

	wr.templateWorkers.AddAll(templated)
	log.Printf("[*] Loaded %d templated workers", len(templated))
}
