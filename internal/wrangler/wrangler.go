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
	DiscoveryWorkersInit(templates []models.Worker, inScope []string, scopeDir string)
	FlattenScopes(paths string) ([]string, error)
	startScanProcess()
	templateScanners(workers []models.Worker)
}

// wranglerRepository is our concrete implementation of the interface.
type wranglerRepository struct {
	cli                     models.CLI
	hostDiscoveryWorkers    *concurrency.Registry[models.Worker]
	serviceDiscoveryWorkers *concurrency.Registry[models.Worker]
	serviceEnum             *concurrency.Registry[models.Target]
	staticWorkers           *concurrency.Registry[models.Worker]
	staticTargets           *concurrency.Registry[models.Target]
	templateWorkers         *concurrency.Registry[models.Worker]
	templateTargets         *concurrency.Registry[models.Target]
}

// NewWranglerRepository constructs our repository and sets up signals.
func NewWranglerRepository(cli models.CLI) WranglerRepository {
	return &wranglerRepository{
		cli:                     cli,
		hostDiscoveryWorkers:    concurrency.NewRegistry[models.Worker](WorkerEquals),
		serviceDiscoveryWorkers: concurrency.NewRegistry[models.Worker](WorkerEquals),
		serviceEnum:             concurrency.NewRegistry[models.Target](TargetEquals),
		staticWorkers:           concurrency.NewRegistry[models.Worker](WorkerEquals),
		staticTargets:           concurrency.NewRegistry[models.Target](TargetEquals),
		templateWorkers:         concurrency.NewRegistry[models.Worker](WorkerEquals),
		templateTargets:         concurrency.NewRegistry[models.Target](TargetEquals),
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
	wr.loadWorkers()
	wr.startScanProcess()
}

// setupInternal initialises project resources, directories and files
func (wr *wranglerRepository) setupInternal(project *models.Project) {
	log.Printf("[*] Initiating Project '%s' with Execution ID: '%s'", wr.cli.ProjectName, project.ExecutionID.String())
	logProjectDetails(project)

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

		err = files.CreateDir(scopeDir)
		if err != nil {
			fmt.Printf("[!] Failed to create scope directory: %v\n", err)
			os.Exit(1)
		}
		inScopePath, err := files.WriteSliceToFile(scopeDir, inScopeFile, inScope)
		if err != nil {
			fmt.Printf("[!] Failed to write targets to file: %v\n", err)
			os.Exit(1)
		}

		project.InScopeFile = inScopePath
		fmt.Printf("[*] Created single scope file: %s\n", project.InScopeFile)
	}
	project.InScopeHosts = inScope
}

// loadWorkers loads template and static scanner workers from YAML file
func (wr *wranglerRepository) loadWorkers() {
	hdw := make([]models.Worker, 0)
	sdw := make([]models.Worker, 0)
	static := make([]models.Worker, 0)
	templated := make([]models.Worker, 0)

	scans, aliases, scoping, err := serializers.LoadScansFromYAML(wr.cli.PatternFile)
	if err != nil {
		log.Printf("[!] Unable to load scans: %scan", err)
		panic(err.Error())
	}

	for _, scope := range scoping {
		for i := range scans {
			if scans[i].Tool == scope.Tool {
				scans[i].ScopeArg = scope.Arg
			}
		}
	}

	// Check binaries are installed in PATH
	err = setToolBinPath(scans)
	if err != nil {
		fmt.Printf("[!] Error encountered validating worker binaries: %s", err.Error())
		os.Exit(1)
	}
	initializeServiceAliases(aliases.Aliases)

	log.Printf("[*] Loaded %d scans and %d service aliases from YAML",
		len(scans), len(aliases.Aliases))

	var workers []models.Worker
	for _, scan := range scans {
		w := wr.NewWorkerWithService(&scan)
		workers = append(workers, w)
	}

	for _, worker := range workers {
		if worker.IsHostDiscovery {
			hdw = append(hdw, worker)
		} else if worker.IsServiceDiscovery {
			sdw = append(sdw, worker)
		} else if portsAreHardcoded(&worker) {
			static = append(static, worker)
		} else {
			templated = append(templated, worker)
		}
	}

	wr.hostDiscoveryWorkers.AddAll(hdw)
	log.Printf("[*] Loaded %d host discovery workers", len(hdw))

	wr.serviceDiscoveryWorkers.AddAll(sdw)
	log.Printf("[*] Loaded %d service discovery workers", len(sdw))

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

// TODO: THIS
func setToolBinPath(scans []models.Scan) error {
	// Create map of unique tools (pre-allocated)
	uniqueTools := make(map[string]struct{}, len(scans))
	for _, scan := range scans {
		uniqueTools[scan.Tool] = struct{}{} // More efficient than bool
	}

	// Find binaries for unique tools
	toolToBin := make(map[string]helpers.BinaryInfo, len(uniqueTools))
	uniqueBins := make(map[string]helpers.BinaryInfo)
	var missingBinaries []string

	for tool := range uniqueTools {
		bin := helpers.FindBinary(tool)
		if bin.Error != nil {
			missingBinaries = append(missingBinaries, fmt.Sprintf("'%s': %v", tool, bin.Error))
			continue
		}

		toolToBin[tool] = bin

		// Store unique binaries for logging
		if _, exists := uniqueBins[bin.Name]; !exists {
			uniqueBins[bin.Name] = bin
		}
	}

	// Report all missing binaries at once
	if len(missingBinaries) > 0 {
		return fmt.Errorf("the following binaries do not appear to be installed: %s",
			strings.Join(missingBinaries, ", "))
	}

	// Properly update the original scans
	for i := range scans {
		if bin, ok := toolToBin[scans[i].Tool]; ok {
			scans[i].Tool = bin.PathInPATH
		}
	}

	// Log installed binaries information (only if any found)
	if len(uniqueBins) > 0 {
		log.Println("==== Installed Binaries ====")
		log.Println("==== Validate binaries and paths ====")
		log.Print("PATH")
		log.Printf("  ├─ $PATH: %s", os.Getenv("PATH"))

		for _, bin := range uniqueBins {
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

	return nil
}

func logProjectDetails(project *models.Project) {
	name := strings.Split(project.Name, "_")
	log.Println("==== Project Details ====")
	log.Printf("Project Name: %s", strings.Join(name[1:], "_"))
	log.Printf("  ├─ Execution ID: %s", project.ExecutionID)
	log.Printf("  ├─ In-Scope File: %s", project.InScopeFile)
	log.Printf("  ├─ Exclude-Scope File: %s", project.ExcludeScopeFile)
	log.Printf("  ├─ Report Directory Parent: %s", project.ReportDirParent)

	if project.ProjectReportPath != "" {
		log.Printf("  ├─ Project Report Path: %s", project.ProjectReportPath)
	} else {
		log.Printf("  ├─ Project Report Path: Not set")
	}

	if project.ProjectBase != "" {
		log.Printf("  ├─ Project Base: %s", project.ProjectBase)
	} else {
		log.Printf("  ├─ Project Base: Not set")
	}
	log.Println()
}
