package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/concurrency"
	"Wrangler/pkg/helpers"
	"Wrangler/pkg/models"
	"Wrangler/pkg/serializers"
	"fmt"
	"github.com/google/uuid"
	"log"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
)

// WorkerStop is used to tell a worker goroutine to shut down.
const WorkerStop = "STOP"

var (
	project *models.Project
	// Atomics
	discoveryDone   atomic.Bool
	serviceEnumDone atomic.Bool

	scopeDir            = "discovered"
	inScopeFile         = "in_scope.txt"
	excludeFile         = "out_of_scope.txt"
	batchSize           = 200
	serviceAliasManager *models.ServiceAliasManager

	// Mao scan tools to their binary path in the PATH variable
	binaries = make(map[string]string)

	// Channels
	sigCh = make(chan os.Signal, 1)
	errCh = make(chan error, 1)
)

// WranglerRepository defines the interface for creating/managing projects.
type WranglerRepository interface {
	NewProject() *models.Project
	ProjectInit(project *models.Project)
	setupInternal(project *models.Project)
	DiscoveryScan(workers []models.Worker, wg *sync.WaitGroup)
	startWorkers(project *models.Project, workers []models.Worker, targets []*models.Target, parentWg *sync.WaitGroup)
	DiscoveryWorkersInit(inScope []string, scopeDir string)
	FlattenScopes(paths string) ([]string, error)
	startScanProcess(inScope []string)
	templateScanners(workers []models.Worker)
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

	eid := uuid.Must(uuid.NewUUID())
	project = &models.Project{
		ExecutionID:      eid,
		Name:             eid.String() + "_" + wr.cli.ProjectName,
		ExcludeScopeFile: wr.cli.ScopeExclude,
		ReportDirParent:  wr.cli.Output,
		TempPrefix:       ".temp",
	}

	log.Printf("[*] Project Execution ID: %s", eid.String())

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

	report := path.Join(cwd, wr.cli.Output, helpers.SpacesToUnderscores(project.Name))
	err = files.CreateDir(report)
	if err != nil {
		fmt.Printf("[!] Failed to create report directory: %v\n", err)
		os.Exit(1)
	}
	project.ReportDirParent = report
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
		if err != nil {
			os.Exit(1)
		}
		project.ExcludeScopeFile = exclude
	}

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

	var inScope []string
	if wr.cli.ScopeFiles != "" {
		inScope, err = wr.FlattenScopes(wr.cli.ScopeFiles)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}

		// Create scope directory if it doesn't exist
		err = files.CreateDir(scopeDir)
		if err != nil {
			fmt.Printf("[!] Failed to create scope directory: %v\n", err)
			os.Exit(1)
		}

		// Write all targets to the single in-scope file
		inScopePath, err := files.WriteSliceToFile(scopeDir, inScopeFile, inScope)
		if err != nil {
			fmt.Printf("[!] Failed to write targets to file: %v\n", err)
			os.Exit(1)
		}

		// Update the project's InScopeFile to point to the created file
		project.InScopeFile = inScopePath
		fmt.Printf("[*] Created single scope file: %s\n", project.InScopeFile)
	}

	wr.loadWorkers()
	wr.startScanProcess(inScope)
}

func (wr *wranglerRepository) loadWorkers() {
	static := make([]models.Worker, 0)
	templated := make([]models.Worker, 0)

	scans, aliases, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("[!] Unable to load scans: %s", err)
		panic(err.Error())
	}

	validateScanToolBinaries(scans)
	initializeServiceAliases(aliases.Aliases)

	log.Printf("[*] Loaded %d scans and %d service aliases from YAML",
		len(scans), len(aliases.Aliases))

	var workers []models.Worker
	for _, s := range scans {
		w := wr.NewWorkerWithService(s.Tool, s.Args, s.Protocol, s.Description, s.TargetService)
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

func initializeServiceAliases(aliases []models.ServiceAlias) {
	serviceAliasManager = NewServiceAliasManager(aliases)
}

func serviceMatches(service models.Service, targetServices []string) bool {
	if len(targetServices) == 0 {
		return false
	}
	serviceName := service.Name
	return serviceAliasManager.IsServiceMatch(serviceName, targetServices)
}

func validateScanToolBinaries(scans []models.ScanDetails) {
	unique := make(map[string]bool)
	for _, scan := range scans {
		if exists := unique[scan.Tool]; !exists {
			unique[scan.Tool] = true
		}
	}
	found := make(map[string]helpers.BinaryInfo)
	for key := range unique {
		bin := helpers.FindBinary(key)
		if bin.Error != nil {
			log.Fatalf("[!] Binary '%s' does not appear to be installed': '%v'", key, bin.Error)
		}
		if _, exists := found[bin.Name]; !exists {
			binaries[bin.Name] = bin.PathInPATH
			found[key] = bin
		}
	}

	if len(found) > 0 {
		log.Println("==== Installed Binaries ====")
	}

	log.Println("==== Validate binaries and paths ====")
	log.Print("PATH")
	log.Printf("  ├─ $PATH: %s", os.Getenv("PATH"))
	for _, bin := range found {
		log.Printf("Binary: %s", bin.Name)
		log.Printf("  ├─ Path in PATH: %s", bin.PathInPATH)
		log.Printf("  ├─ Real Path: %s", bin.RealPath)
		log.Printf("  ├─ Is Symlink: %t", bin.IsSymlink)

		if bin.PackageOwner != "" {
			log.Printf("  ├─ Package Owner: %s", bin.PackageOwner)
		}
		if bin.Distribution != "" {
			log.Printf("  ├─ Distribution: %s", bin.Distribution)
			if bin.DistVersion != "" {
				log.Printf("  │  └─ Version: %s", bin.DistVersion)
			}
		}

		if bin.InstallSource != "" {
			log.Printf("  └─ Install Source: %s", bin.InstallSource)
		} else {
			log.Println("  └─ Install Source: Unknown")
		}

		log.Println()
	}
}

func getBinaryPath(name string) string {
	return binaries[name]
}
