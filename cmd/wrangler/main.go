package main

import (
	"Wrangler/internal/wrangler"
	"Wrangler/pkg/models"
	"fmt"
	"github.com/alecthomas/kong"
	"log"
	"sync"
	"time"
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

	// Initialise a new project
	wr := wrangler.NewWranglerRepository(cli)
	project = wr.NewProject()
	wr.ProjectInit(project)
	// Get broadcast channels for monitoring
	serviceEnumBC := wr.GetServiceEnumBroadcast()
	fullScanBC := wr.GetFullScanBroadcast()

	// Create monitoring subscription for service enumeration
	serviceEnumMonitor := serviceEnumBC.Subscribe(100)

	// Start service enumeration monitor
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorServiceEnum(serviceEnumMonitor)
	}()

	// Create monitoring subscription for full scan
	fullScanMonitor := fullScanBC.Subscribe(100)

	// Start full scan monitor
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorFullScan(fullScanMonitor)
	}()

	// Wait for all monitoring to complete
	wg.Wait()

}

// monitorServiceEnum logs targets from the service enumeration channel
func monitorServiceEnum(ch <-chan models.Target) {
	log.Println("Starting service enumeration monitor...")
	targetCount := 0

	for target := range ch {
		targetCount++
		log.Printf("[SERVICE-ENUM-MONITOR] Found target: %s", target.Host)

		// Process the target without affecting the original workflow
		// For example, update a UI, store in a database, etc.
	}

	log.Printf("[SERVICE-ENUM-MONITOR] Finished monitoring with %d targets", targetCount)
}

// monitorFullScan logs targets from the full scan channel
func monitorFullScan(ch <-chan models.Target) {
	log.Println("Starting full scan monitor...")
	targetCount := 0
	portCount := 0

	for target := range ch {
		targetCount++
		portCount += len(target.Ports)
		log.Printf("[FULL-SCAN-MONITOR] Found target: %s with %d ports",
			target.Host, len(target.Ports))

		// Process the target without affecting the original workflow
		// For example, update a UI, store in a database, etc.
	}

	log.Printf("[FULL-SCAN-MONITOR] Finished monitoring with %d targets and %d ports",
		targetCount, portCount)
}

// Example of a real-time status tracker
type StatusTracker struct {
	mu             sync.RWMutex
	livehostCount  int
	serviceCount   int
	lastUpdated    time.Time
	completedHosts map[string]bool
	completedPorts map[string]int
}

func NewStatusTracker() *StatusTracker {
	return &StatusTracker{
		lastUpdated:    time.Now(),
		completedHosts: make(map[string]bool),
		completedPorts: make(map[string]int),
	}
}

func (st *StatusTracker) UpdateFromTarget(target models.Target) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if !st.completedHosts[target.Host] {
		st.livehostCount++
		st.completedHosts[target.Host] = true
	}

	currentPorts := st.completedPorts[target.Host]
	newPorts := len(target.Ports)
	if newPorts > currentPorts {
		st.serviceCount += (newPorts - currentPorts)
		st.completedPorts[target.Host] = newPorts
	}

	st.lastUpdated = time.Now()
}

func (st *StatusTracker) GetStatus() string {
	st.mu.RLock()
	defer st.mu.RUnlock()

	return fmt.Sprintf("Live hosts: %d, Services: %d, Last updated: %s",
		st.livehostCount, st.serviceCount, st.lastUpdated.Format("15:04:05"))
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
