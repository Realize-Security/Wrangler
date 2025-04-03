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
	"syscall"
)

var (
	scopeDirectory = "./assessment_scope/"
	inScopeFile    = "in_scope.txt"
	outOfScopeFile = "out_of_scope.txt"
	nonRootUser    = ""
	projectRoot    = ""
)

type CLI struct {
	ProjectName  string `name:"project-name" help:"Name for the project" required:""`
	ScopeFiles   string `name:"scope" help:"Files containing target IP addresses or FQDNs" required:"" type:"path"`
	ScopeExclude string `name:"exclude" help:"ExcludeScopeFile from scans" type:"path"`
	Output       string `name:"output" help:"Output folder (defaults to stdout)"`
	PatternFile  string `name:"scan-patterns" help:"YML file containing scan patterns"`
	NonRootUser  string `name:"non-root-user" help:"Non-root user who will own report files." required:""`
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

	cwd, err := os.Getwd()
	if err != nil {
		log.Panic(err)
	}
	projectRoot = cwd
	nonRootUser = cli.NonRootUser

	scanArgs, err := loadPatternsFromYAML(cli.PatternFile)
	if err != nil {
		log.Printf("unable to load scans: %s", err.Error())
		// Decide whether to return or keep going based on your preference
	}
	log.Printf("Loaded %d scans from YAML file", len(scanArgs))

	var workers []wrangler.Worker
	for i, pattern := range scanArgs {
		worker := wrangler.Worker{
			ID:          i,
			Type:        pattern.Tool,
			Command:     pattern.Tool,
			Args:        pattern.Args,
			Description: pattern.Description,
		}
		workers = append(workers, worker)
	}

	scope, err := flattenScopeFiles(cli.ScopeFiles, inScopeFile)
	if err != nil {
		fmt.Printf(err.Error())
		return
	}

	var exclude string
	if cli.ScopeExclude != "" {
		exclude, err = flattenScopeFiles(cli.ScopeExclude, outOfScopeFile)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}
	}

	reportPath, err := createReportDirectory(cli.Output, cli.ProjectName)
	if err != nil {
		fmt.Printf(err.Error())
		return
	}

	// Always run cleanupPermissions()
	defer func(reports, scopes string) {
		err := cleanupPermissions(reports, scopes)
		if err != nil {
			log.Printf("Error during cleanupPermissions(): %v", err)
		}
	}(reportPath, scopeDirectory)

	wranglerRepo := wrangler.NewWranglerRepository()
	project := wranglerRepo.NewProject(cli.ProjectName, scope, exclude, cli.Output)
	project.Workers = workers
	project.ReportDir = reportPath

	wranglerRepo.ProjectInit(project)

	wg := wranglerRepo.StartWorkers(project)

	// 2. Set up channels & listeners
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)

	// 3. Launch goroutines to handle signals and to drain worker responses
	setupSignalHandler(sigCh, project.Workers)
	drainWorkerResponses(project.Workers)
	drainWorkerErrors(project.Workers, errCh)
	listenToWorkerErrors(errCh, project.Workers)

	// 4. Wait until all workers finish
	wg.Wait()
	log.Println("All workers have stopped. Exiting now.")
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

func flattenScopeFiles(paths, filename string) (string, error) {
	scopes := strings.Split(paths, ",")
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if _, err := os.Stat(scope); os.IsNotExist(err) {
			return "", fmt.Errorf("file %s does not exist", scope)
		}
	}
	var allIps []string

	for _, scope := range scopes {
		ips, err := files.FileLinesToSlice(scope)
		if err != nil {
			return "", fmt.Errorf("unable to parse: %s. error: %s", scope, err.Error())
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
		return "", err
	}

	err := files.CreateDir(scopeDirectory)
	if err != nil {
		return "", fmt.Errorf("unable to create directory: %s", err.Error())
	}

	fullPath := path.Join(projectRoot, scopeDirectory, filename)
	err = files.WriteFile(fullPath, final)
	if err != nil {
		return "", fmt.Errorf("unable to create file: %s", err.Error())
	}
	return fullPath, nil
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

// setupSignalHandler listens for Ctrl+C or kill signals
// and gracefully stops all workers if such a signal arrives.
func setupSignalHandler(sigCh <-chan os.Signal, workers []wrangler.Worker) {
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

// drainWorkerResponses sets up a goroutine per worker to listen
// to the WorkerResponse channel and logs all messages.
func drainWorkerResponses(workers []wrangler.Worker) {
	for _, w := range workers {
		w := w // capture loop variable
		go func() {
			for resp := range w.WorkerResponse {
				log.Printf("[Worker %d] %s\n", w.ID, resp)
			}
		}()
	}
}

// drainWorkerErrors watches the ErrorChan of each Worker.
// If any non-nil error arrives, we send it to errCh.
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
func listenToWorkerErrors(errCh <-chan error, workers []wrangler.Worker) {
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
