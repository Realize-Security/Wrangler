package main

import (
	"Wrangler/internal/files"
	"Wrangler/internal/wrangler"
	"Wrangler/pkg/models"
	"Wrangler/pkg/validators"
	"fmt"
	"github.com/alecthomas/kong"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"strings"
)

var (
	fullScope  []string
	outOfScope []string
)

type CLI struct {
	ProjectName string `name:"project-name" help:"Name for the project" required:""`
	ScopeFiles  string `name:"scope" help:"Files containing target IP addresses or FQDNs" required:"" type:"path"`
	Exclude     string `name:"exclude" help:"Exclude from scans" type:"path"`
	Output      string `name:"output" help:"Output folder (defaults to stdout)"`
	PatternFile string `name:"scan-patterns" help:"YML file containing scan patterns"`
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

	wranglerRepo := wrangler.NewWranglerRepository()
	project := wranglerRepo.NewProject(cli.ProjectName, fullScope, outOfScope)
	project.Workers = workers
	wranglerRepo.ProjectInit(project)

	wg := wranglerRepo.StartWorkers(project)
	wg.Wait() // Wait here until all workers finish
	fmt.Println("All workers have stopped. Exiting now.")
}

func description() string {
	return `
Run multiple Nmap scans

Examples:
  ./wrangler --scope=ip_addresses.txt --output=report_dir --scan-patterns=some_patterns.yml
  ./wrangler --scope=ip_addresses.txt,ip_addresses2.txt --output=report_dir --scan-patterns=some_patterns.yml
`
}

func (c *CLI) Validate(ctx *kong.Context) error {

	if _, err := os.Stat(c.Output); os.IsNotExist(err) {
		return fmt.Errorf("folder %s does not exist", c.Output)
	}

	if c.PatternFile != "" {
		if _, err := os.Stat(c.PatternFile); os.IsNotExist(err) {
			return fmt.Errorf("pattern file %s does not exist", c.PatternFile)
		}
	}

	// In-scope assets
	scopes := strings.Split(c.ScopeFiles, ",")
	for _, file := range scopes {
		file = strings.TrimSpace(file)
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", file)
		}

		targets, err := files.FileLinesToSlice(file)
		if err != nil {
			return fmt.Errorf("unable to parse: %s", file)
		}

		if err = validators.ValidateScope(targets); err != nil {
			return fmt.Errorf("file %s contains invalid scope item. Error: '%s'", file, err.Error())
		}
		for _, target := range targets {
			fullScope = append(fullScope, target)
		}
	}

	// Out of scope exclusions
	if c.Exclude != "" {
		exclude := strings.Split(c.Exclude, ",")
		for _, file := range exclude {
			file = strings.TrimSpace(file)
			if _, err := os.Stat(file); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", file)
			}

			targets, err := files.FileLinesToSlice(file)
			if err != nil {
				return fmt.Errorf("unable to parse: %s", file)
			}

			if err = validators.ValidateScope(targets); err != nil {
				return fmt.Errorf("file %s contains invalid scope item. Error: '%s'", file, err.Error())
			}
			for _, target := range targets {
				outOfScope = append(outOfScope, target)
			}
		}
	}
	return nil
}
