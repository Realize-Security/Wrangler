package main

import (
	"Wrangler/internal/files"
	"Wrangler/internal/wrangler"
	"Wrangler/pkg/models"
	"fmt"
	"github.com/alecthomas/kong"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"path"
	"strings"
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
			ID:      i,
			Type:    pattern.Tool,
			Command: pattern.Tool,
			Args:    pattern.Args,
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

	wranglerRepo := wrangler.NewWranglerRepository()
	project := wranglerRepo.NewProject(cli.ProjectName, scope, exclude)
	project.Workers = workers

	wranglerRepo.ProjectInit(project)

	wg := wranglerRepo.StartWorkers(project)

	//for _, w := range project.Workers {
	//	w := w
	//	go func() {
	//		for resp := range w.WorkerResponse {
	//			fmt.Printf("[Worker %d] %s\n", w.ID, resp)
	//		}
	//	}()
	//}

	wg.Wait()
	fmt.Println("All workers have stopped. Exiting now.")
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
	ipLen := 0
	scopes := strings.Split(paths, ",")
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if _, err := os.Stat(scope); os.IsNotExist(err) {
			return "", fmt.Errorf("file %s does not exist", scope)
		}
		ipLen = ipLen + len(scope)
	}
	var allIps []string
	final := make([]string, ipLen)
	uniqueIps := make(map[string]bool, ipLen)

	for _, scope := range scopes {
		ips, err := files.FileLinesToSlice(scope)
		if err != nil {
			return "", fmt.Errorf("unable to parse: %s. error: %s", scope, err.Error())
		}
		allIps = append(allIps, ips...)
	}

	for i, ip := range allIps {
		if !uniqueIps[ip] {
			uniqueIps[ip] = true
			final[i] = ip
		}
	}

	err := files.CreateDir(scopeDirectory)
	if err != nil {
		return "", fmt.Errorf("unable to create directory: %s", err.Error())
	}

	fullPath := path.Join(scopeDirectory, filename)
	err = files.WriteFile(fullPath, final)
	if err != nil {
		return "", fmt.Errorf("unable to create file: %s", err.Error())
	}
	return fullPath, nil
}
