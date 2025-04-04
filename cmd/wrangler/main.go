package main

import (
	"Wrangler/internal/files"
	"Wrangler/internal/wrangler"
	"Wrangler/pkg/helpers"
	"Wrangler/pkg/models"
	"Wrangler/pkg/validators"
	"fmt"
	"github.com/alecthomas/kong"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	scopeDirectory = "./assessment_scope/"
	inScopeFile    = "in_scope.txt"
	outOfScopeFile = "out_of_scope.txt"
	nonRootUser    = ""
	projectRoot    = ""
	scanBatchSize  = 200
)

// Set up channels & listeners needed by all workflows
var (
	fullScan = make(chan string)
	sigCh    = make(chan os.Signal, 1)
	errCh    = make(chan error, 1)
)

var (
	wranglerRepo wrangler.WranglerRepository
	project      *wrangler.Project
)

type CLI struct {
	ProjectName  string `name:"project-name" help:"Name for the project" required:""`
	ScopeFiles   string `name:"scope" help:"Files containing target IP addresses or FQDNs" required:"" type:"path"`
	NonRootUser  string `name:"non-root-user" help:"Non-root user who will own report files." required:""`
	ScopeExclude string `name:"exclude" help:"ExcludeScopeFile from scans" type:"path"`
	Output       string `name:"output" help:"Output folder (defaults to stdout)"`
	PatternFile  string `name:"scan-patterns" help:"YML file containing scan patterns"`
	//BatchSize    string `name:"batch-size" help:"Number of hosts to add to Nmap batches" required:""`
	RunDiscovery bool `name:"discover" help:"Run ICMP and port knocking checks to establish host availability"`
}

func main() {
	var cli CLI
	_ = kong.Parse(&cli,
		kong.Description(description()),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}),
	)

	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	cwd, err := os.Getwd()
	if err != nil {
		log.Panic(err)
	}
	projectRoot = cwd
	nonRootUser = cli.NonRootUser

	// Load primary primaryWorkers from file
	scanArgs, err := loadPatternsFromYAML(cli.PatternFile)
	if err != nil {
		log.Printf("unable to load scans: %s", err.Error())
		// Decide whether to return or keep going based on your preference
	}
	log.Printf("Loaded %d scans from YAML file", len(scanArgs))

	reportPath, err := createReportDirectory(cli.Output, cli.ProjectName)
	if err != nil {
		fmt.Printf(err.Error())
		return
	}

	//Initialise primary primaryWorkers
	var primaryWorkers []wrangler.Worker
	for i, pattern := range scanArgs {
		worker := wrangler.Worker{
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
	var excludeScope []string
	if cli.ScopeExclude != "" {
		excludeScope, err = flattenScopes(cli.ScopeExclude)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}
	}
	exclude, err := files.WriteSliceToFile(cwd, scopeDirectory, outOfScopeFile, excludeScope)

	// Initialise cleanupPermissions() to always run when program exits
	defer func(reports, scopes string) {
		err := cleanupPermissions(reports, scopes)
		if err != nil {
			log.Printf("Error during cleanupPermissions(): %v", err)
		}
	}(reportPath, scopeDirectory)

	// Initialise anew project
	wranglerRepo = wrangler.NewWranglerRepository()
	project = wranglerRepo.NewProject(cli.ProjectName, exclude, cli.Output)

	// If discovery is run, this will create a list of hosts to be added to scope.
	// Otherwise, use user-supplied list verbatim

	// First get user-supplied scope
	var inScope []string
	if cli.ScopeFiles != "" {
		inScope, err = flattenScopes(cli.ScopeFiles)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}
	}

	var wgDisc *sync.WaitGroup
	if cli.RunDiscovery {
		wgDisc = initialiseDiscoveryWorkers(inScope)
		go func() {
			wgDisc.Wait()
			log.Println("All discovery workers done.")
			close(fullScan)
		}()
	} else {
		// If no discovery, write scope to file straight away
		inScopeFile, err = files.WriteSliceToFile(cwd, scopeDirectory, inScopeFile, inScope)
		close(fullScan)
	}

	project.InScopeFile = inScopeFile
	project.Workers = primaryWorkers
	project.ReportDir = reportPath

	wranglerRepo.ProjectInit(project)
	wg := wranglerRepo.StartWorkers(project, fullScan, scanBatchSize)

	setupSignalHandler(project.Workers, sigCh)
	drainWorkerErrors(project.Workers, errCh)
	listenToWorkerErrors(project.Workers, errCh)

	// 4. Wait until all primary workers finish
	wg.Wait()
	log.Println("All primaryWorkers have stopped. Exiting now.")
}

func description() string {
	return `
Run multiple Nmap scans

Examples:
  ./wrangler --scope=ip_addresses.txt --output=report_dir --scan-patterns=default_scans.yml
  ./wrangler --scope=ip_addresses.txt,ip_addresses2.txt --output=report_dir --scan-patterns=default_scans.yml
`
}

//------------------------------------------------------
// YAML Loading
//------------------------------------------------------

func loadPatternsFromYAML(filepath string) ([]*models.ScanDetails, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("error reading pattern file: %v", err)
	}

	var config models.ScanConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing pattern file: %v", err)
	}

	patterns := make([]*models.ScanDetails, 0, len(config.Scans))
	for _, entry := range config.Scans {
		patterns = append(patterns, &entry.ScanItem)
	}
	return patterns, nil
}

//------------------------------------------------------
// Scope File Handling
//------------------------------------------------------

func flattenScopes(paths string) ([]string, error) {
	scopes := strings.Split(paths, ",")
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if _, err := os.Stat(scope); os.IsNotExist(err) {
			return nil, fmt.Errorf("file %s does not exist", scope)
		}
	}
	var allIps []string

	for _, scope := range scopes {
		ips, err := files.FileLinesToSlice(scope)
		if err != nil {
			return nil, fmt.Errorf("unable to parse: %s. error: %s", scope, err.Error())
		}
		allIps = append(allIps, ips...)
	}

	ipLen := len(allIps)
	final := make([]string, 0, ipLen)
	uniqueIps := make(map[string]bool, ipLen)

	for _, ip := range allIps {
		if !uniqueIps[ip] {
			uniqueIps[ip] = true
			final = append(final, ip)
		}
	}

	if err := validators.ValidateScope(final); err != nil {
		return nil, err
	}
	return final, nil
}

func initialiseDiscoveryWorkers(inScope []string) *sync.WaitGroup {
	unconfirmed := make(chan string)
	var w []wrangler.Worker
	for i, target := range inScope {
		w = append(w, wrangler.Worker{
			ID:             i,
			Type:           "nmap",
			Target:         target,
			Args:           []string{"-sn", target},
			UserCommand:    make(chan string, 1),
			WorkerResponse: make(chan string),
			ErrorChan:      make(chan error),
		})
	}
	unifyDiscoveryResponseReading(w, unconfirmed, fullScan)
	wg := wranglerRepo.HostDiscoveryScan(w, project.ExcludeScopeFile)

	// Keep your error watchers
	drainWorkerErrors(w, errCh)
	listenToWorkerErrors(w, errCh)

	// The rest is the same
	go batchProcessDiscovery(unconfirmed, scanBatchSize)
	workerTimeout(w)
	setupSignalHandler(w, sigCh)

	return wg
}

func unifyDiscoveryResponseReading(
	workers []wrangler.Worker,
	unconfirmedHostStatus, fullScan chan<- string,
) {
	for _, w := range workers {
		w := w
		go func() {
			for resp := range w.WorkerResponse {
				log.Printf("[Worker %d] %s\n", w.ID, resp)

				if strings.Contains(resp, "Host is up (") {
					fullScan <- w.Target
					continue
				}

				if strings.Contains(resp, "open") || strings.Contains(resp, "closed") &&
					!strings.Contains(resp, "filtered") {
					fullScan <- w.Target
					w.UserCommand <- wrangler.WorkerStop
					continue
				}
				unconfirmedHostStatus <- w.Target
			}
		}()
	}
}

// batchProcessDiscovery processes additional discover for discovery workgroups
func batchProcessDiscovery(unconfirmedHosts <-chan string, n int) {
	var wgMaster []*sync.WaitGroup
	for {
		batch := helpers.ReadNTargetsFromChannel(unconfirmedHosts, n)
		if len(batch) == 0 {
			break
		}
		wg, err := wranglerRepo.PortOpenOrClosedDiscovery(project, batch, "tcp", 1000)
		if err != nil {
			log.Printf("error is batch discovery: %s", err)
			continue
		}
		wgMaster = append(wgMaster, wg)
		// Sleep briefly to give the CPU clock a break
		time.Sleep(time.Second * 1)
	}
	for _, wgc := range wgMaster {
		if wgc != nil {
			wgc.Wait()
		}
	}
}

//------------------------------------------------------
// Report Directory & Cleanup
//------------------------------------------------------

func createReportDirectory(outputDir, projectName string) (string, error) {
	var reportPath string
	if outputDir != "" {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}
		reportPath = path.Join(wd, outputDir, helpers.SpacesToUnderscores(projectName))

		_, err = os.Stat(reportPath)
		if err != nil {
			err = files.CreateDir(reportPath)
			if err != nil {
				return "", err
			}
		}
	}
	return reportPath, nil
}

func cleanupPermissions(reports, scopes string) error {
	fmt.Println("[*] Cleaning up.")
	paths := []string{reports, scopes}

	for _, p := range paths {
		if p == "" {
			continue
		}
		err := files.SetFileAndDirPermsRecursive(nonRootUser, projectRoot, p)
		if err != nil {
			log.Printf("failed to set permissions for %s: %s", p, err.Error())
			return err
		}
	}
	return nil
}

//------------------------------------------------------
// Goroutine Helpers
//------------------------------------------------------

func isOpenOrClosedButNotFiltered(resp string) bool {
	return (strings.Contains(resp, "open") || strings.Contains(resp, "closed")) &&
		!strings.Contains(resp, "filtered")
}

// onePortOpenOrClosed listens for a string to indicate a host is active during a ping scan.
// Adds valid workers to a hostsUp up chan to be fed into scanning
func onePortOpenOrClosed(workers []wrangler.Worker, fullScan chan<- string) {
	for _, w := range workers {
		w := w
		go func() {
			for resp := range w.WorkerResponse {
				if (strings.Contains(resp, "open") || strings.Contains(resp, "closed")) && !strings.Contains(resp, "filtered") {
					fullScan <- w.Target
					w.UserCommand <- wrangler.WorkerStop
				}
			}
		}()
	}
}

// workerTimeout cancels workers which exceed a set (optional) duration
func workerTimeout(workers []wrangler.Worker) {
	for _, w := range workers {
		w := w
		go func() {
			if time.Since(w.Started) >= w.Timeout {
				w.UserCommand <- wrangler.WorkerStop
			}
		}()
	}
}

// setupSignalHandler listens for Ctrl+C or kill signals
// and gracefully stops all workers if such a signal arrives.
func setupSignalHandler(workers []wrangler.Worker, sigCh <-chan os.Signal) {
	go func() {
		<-sigCh
		log.Println("Received interrupt signal, stopping workers...")
		for _, w := range workers {
			if w.CancelFunc != nil {
				w.CancelFunc()
			}
			w.UserCommand <- wrangler.WorkerStop
		}
	}()
}

// drainWorkerErrors watches ErrorChan of each Worker.
// It drains all errors until the channel is closed.
// If a non-nil error arrives, we send it to errCh.
func drainWorkerErrors(workers []wrangler.Worker, errCh chan<- error) {
	for _, w := range workers {
		w := w
		go func() {
			// Listen for any errors until the channel is closed.
			for workerErr := range w.ErrorChan {
				if workerErr != nil {
					errCh <- fmt.Errorf("worker %d encountered an OS error: %w", w.ID, workerErr)
				}
			}
		}()
	}
}

// listenToWorkerErrors will receive the first error from any worker,
// log it, and immediately stop all workers.
func listenToWorkerErrors(workers []wrangler.Worker, errCh <-chan error) {
	go func() {
		err := <-errCh
		log.Printf("FATAL: %v", err)
		// Force all workers to stop
		for _, w := range workers {
			if w.CancelFunc != nil {
				w.CancelFunc()
			}
			w.UserCommand <- wrangler.WorkerStop
		}
	}()
}
