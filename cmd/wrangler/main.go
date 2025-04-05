package main

import (
	"Wrangler/internal/wrangler"
	"Wrangler/pkg/models"
	"github.com/alecthomas/kong"
)

var (
	project *wrangler.Project
)

func main() {
	var cli models.CLI
	_ = kong.Parse(&cli,
		kong.Description(description()),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}),
	)

	// Initialise a new project
	wr := wrangler.NewWranglerRepository(cli)
	project = wr.NewProject()
	wr.ProjectInit(project)
}

func description() string {
	return `
Run multiple Nmap scans

Examples:
  ./wrangler --scope=ip_addresses.txt --output=report_dir --scan-patterns=default_scans.yml
  ./wrangler --scope=ip_addresses.txt,ip_addresses2.txt --output=report_dir --scan-patterns=default_scans.yml
`
}
