package main

import (
	"Wrangler/internal/wrangler"
	"Wrangler/pkg/models"
	"github.com/alecthomas/kong"
)

var (
	project *models.Project
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

	if cli.BatchSize <= 0 {
		cli.BatchSize = 200
	}

	wr := wrangler.NewWranglerRepository(cli)
	project = wr.NewProject()
	wr.ProjectInit(project)
}

func description() string {
	return `
Run multiple Nmap scans

Wrangler is a command-line tool designed to automate and manage multiple Nmap scans against specified target IP addresses or fully qualified domain names (FQDNs). It allows users to define scan scopes, configure output, customize scan patterns, and control execution behavior through a variety of options. The tool is flexible, supporting single or multiple input files, customizable scan patterns via YAML configuration, and options for batch processing and debugging.

Examples:
  ./wrangler --project-name=my_scan --scope=ip_addresses.txt --output=report_dir --scan-patterns=default_scans.yml
  ./wrangler --project-name=my_scan --scope=ip_addresses.txt,ip_addresses2.txt --output=report_dir --scan-patterns=default_scans.yml
  ./wrangler --project-name=my_scan --scope=ip_addresses.txt --exclude=exclude_ips.txt --output=report_dir --batch-size=100 --scan-patterns=default_scans.yml
  ./wrangler --project-name=my_scan --scope=ip_addresses.txt --debug-workers

Options:
  --project-name     Name for the project (required)
  --scope            Files containing target IP addresses or FQDNs (required, path)
  --exclude          File listing IPs/FQDNs to exclude from scans (path)
  --output           Output folder (defaults to stdout)
  --scan-patterns    YML file containing scan patterns
  --batch-size       Number of hosts to add to Nmap batches
  --debug-workers    Add print statements for worker output

Notes:
  - Scope and exclude files should contain one IP/FQDN per line.
  - The --scan-patterns YAML file allows customization of Nmap options (e.g., ports, scan types).
  - Use --discover to filter unresponsive hosts, which may optimize scan time.
  - Ensure the output directory exists and is writable when using --output.
`
}
