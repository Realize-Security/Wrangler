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
)

type CLI struct {
	ProjectName  string `name:"project-name" help:"Name for the project" required:""`
	ScopeFiles   string `name:"scope" help:"Files containing target IP addresses or FQDNs" required:"" type:"path"`
	ScopeExclude string `name:"exclude" help:"ExcludeScopeFile from scans" type:"path"`
	Output       string `name:"output" help:"Output folder (defaults to stdout)"`
	PatternFile  string `name:"scan-patterns" help:"YML file containing scan patterns"`
}

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

	patterns := make([]*models.ScanDetails, 0)

	yamlPatterns, err := loadPatternsFromYAML(cli.PatternFile)
	if err != nil {
		fmt.Errorf("unable to load patterns: %s", err.Error())
	}
	log.Printf("Loaded %d patterns from YAML file", len(yamlPatterns))
	patterns = append(patterns, yamlPatterns...)

	var workers []wrangler.Worker
	for i, pattern := range patterns {
		worker := wrangler.Worker{
			ID:          i,
			Type:        pattern.Tool,
			Command:     pattern.Tool,
			Args:        pattern.Args,
			Description: pattern.Description,
		}
		workers = append(workers, worker)
		i++
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

	wranglerRepo := wrangler.NewWranglerRepository()
	project := wranglerRepo.NewProject(cli.ProjectName, scope, exclude, cli.Output)
	project.Workers = workers
	project.ReportDir = reportPath

	wranglerRepo.ProjectInit(project)

	wg := wranglerRepo.StartWorkers(project)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Received interrupt signal, stopping workers...")
		for _, w := range project.Workers {
			if w.CancelFunc != nil {
				w.CancelFunc()
			}
			w.UserCommand <- wrangler.WorkerStop
		}

	}()

	errCh := make(chan error, 1)

	// Drain worker responses
	for _, w := range project.Workers {
		w := w
		go func() {
			for resp := range w.WorkerResponse {
				// Log everything
				log.Printf("[Worker %d] %s\n", w.ID, resp)

				// If it includes "error:" or some known substring, treat it as a fatal error
				if strings.Contains(resp, " error: ") {
					errCh <- fmt.Errorf("worker %d failed: %s", w.ID, resp)
				}
			}
		}()
	}
	go func() {
		// The moment we see an error from any worker, stop everything
		err := <-errCh
		log.Printf("FATAL: %v", err)

		// Force all workers to stop
		for _, w := range project.Workers {
			if w.CancelFunc != nil {
				w.CancelFunc()
			}
			w.UserCommand <- wrangler.WorkerStop
		}
	}()

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
	final := make([]string, ipLen)
	uniqueIps := make(map[string]bool, ipLen)

	for i, ip := range allIps {
		if !uniqueIps[ip] {
			uniqueIps[ip] = true
			final[i] = ip
		}
	}

	if err := validators.ValidateScope(final); err != nil {
		return "", err
	}

	err := files.CreateDir(scopeDirectory)
	if err != nil {
		return "", fmt.Errorf("unable to create directory: %s", err.Error())
	}

	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("unable to get current directory: %s", err.Error())
	}

	fullPath := path.Join(wd, scopeDirectory, filename)
	err = files.WriteFile(fullPath, final)
	if err != nil {
		return "", fmt.Errorf("unable to create file: %s", err.Error())
	}
	return fullPath, nil
}

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
