package main

import (
	"Wrangler/internal/wrangler"
	"Wrangler/pkg/models"
	"github.com/alecthomas/kong"
	"log"
	"sync"
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

	wr := wrangler.NewWranglerRepository(cli)
	project = wr.NewProject()
	serviceEnumBC := wr.GetServiceEnumBroadcast()
	fullScanBC := wr.GetFullScanBroadcast()

	// Create monitoring subscription for service enumeration
	serviceEnumMonitor := serviceEnumBC.Subscribe(100)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorServiceEnum(serviceEnumMonitor)
	}()

	fullScanMonitor := fullScanBC.Subscribe(100)
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorFullScan(fullScanMonitor)
	}()

	wr.ProjectInit(project)
	wg.Wait()
}

// monitorServiceEnum logs targets from the service enumeration channel
func monitorServiceEnum(ch <-chan models.Target) {
	log.Println("Starting service enumeration monitor...")
	targetCount := 0

	for target := range ch {
		targetCount++
		log.Printf("[SERVICE-ENUM-MONITOR] Found target: %s", target.Host)
	}

	log.Printf("[SERVICE-ENUM-MONITOR] Finished monitoring with %d targets", targetCount)
}

// monitorFullScan logs targets from the full scan channel
func monitorFullScan(ch <-chan models.Target) {
	log.Println("[*] Starting full scan monitor...")
	targetCount := 0
	portCount := 0

	for target := range ch {
		targetCount++
		portCount += len(target.Ports)
		log.Printf("[FULL-SCAN-MONITOR] Found target: %s with %d ports",
			target.Host, len(target.Ports))
	}

	log.Printf("[FULL-SCAN-MONITOR] Finished monitoring with %d targets and %d ports",
		targetCount, portCount)
}

func description() string {
	return `
Run multiple Nmap scans

Wrangler is a command-line tool designed to automate and manage multiple Nmap scans against specified target IP addresses or fully qualified domain names (FQDNs). It allows users to define scan scopes, configure output, customize scan patterns, and control execution behavior through a variety of options. The tool is flexible, supporting single or multiple input files, customizable scan patterns via YAML configuration, and options for batch processing and debugging.

Examples:
  ./wrangler --project-name=my_scan --scope=ip_addresses.txt --non-root-user=analyst --output=report_dir --scan-patterns=default_scans.yml
  ./wrangler --project-name=my_scan --scope=ip_addresses.txt,ip_addresses2.txt --non-root-user=analyst --output=report_dir --scan-patterns=default_scans.yml
  ./wrangler --project-name=my_scan --scope=ip_addresses.txt --non-root-user=analyst --exclude=exclude_ips.txt --output=report_dir --batch-size=100 --scan-patterns=custom_scans.yml
  ./wrangler --project-name=my_scan --scope=ip_addresses.txt --non-root-user=analyst --discover --debug-workers

Options:
  --project-name      Name for the project (required)
  --scope            Files containing target IP addresses or FQDNs (required, path)
  --non-root-user    Non-root user who will own report files (required)
  --exclude          File listing IPs/FQDNs to exclude from scans (path)
  --output           Output folder (defaults to stdout)
  --scan-patterns    YML file containing scan patterns
  --batch-size       Number of hosts to add to Nmap batches
  --discover         Run ICMP and port knocking checks to establish host availability
  --debug-workers    Add print statements for worker output

Notes:
  - Scope and exclude files should contain one IP/FQDN per line.
  - The --scan-patterns YAML file allows customization of Nmap options (e.g., ports, scan types).
  - Use --discover to filter unresponsive hosts, which may optimize scan time.
  - Ensure the output directory exists and is writable when using --output.
`
}
