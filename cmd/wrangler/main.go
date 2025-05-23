package main

import (
	"Wrangler/internal/wrangler"
	"Wrangler/pkg/models"
	"fmt"
	"github.com/alecthomas/kong"
	"io"
	"log"
	"os"
	"path/filepath"
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

	if cli.BatchSize <= 0 {
		cli.BatchSize = 200
	}

	wr := wrangler.NewWranglerRepository(cli)
	project = wr.NewProject()
	if err := setupLogging(cli.LogFile, project.Name, project.ExecutionID.String(), cli.DebugWorkers); err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}
	wr.ProjectInit(project)
}

// setupLogging configures logging to write to both stdout and an optional file
func setupLogging(logFilePath string, projectName, execId string, debugEnabled bool) error {
	logWriters := []io.Writer{os.Stdout}

	if logFilePath != "" {
		logDir := filepath.Dir(logFilePath)
		if logDir != "." && logDir != "/" {
			if err := os.MkdirAll(logDir, 0755); err != nil {
				return fmt.Errorf("failed to create log directory: %w", err)
			}
		}

		fileInfo, err := os.Stat(logFilePath)
		if err == nil && fileInfo.IsDir() {
			timestamp := time.Now().Format("20060102_150405")
			logFilePath = filepath.Join(logFilePath, fmt.Sprintf("wrangler_%s_%s.log", projectName+"_"+execId, timestamp))
		}

		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}

		logWriters = append(logWriters, logFile)

		fmt.Printf("Logging output to: %s\n", logFilePath)
	}

	// Configure the default logger to use multiple writers
	multiWriter := io.MultiWriter(logWriters...)
	log.SetOutput(multiWriter)

	// Set log flags based on debug setting
	if debugEnabled {
		// Debug mode: include file and line number
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	} else {
		// Normal mode: just date and time
		log.SetFlags(log.Ldate | log.Ltime)
	}

	return nil
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
  ./wrangler --project-name=my_scan --scope=ip_addresses.txt --log-file=scan.log --output=report_dir --scan-patterns=default_scans.yml
  ./wrangler --project-name=my_scan --scope=ip_addresses.txt --log-file=logs/ --output=report_dir --scan-patterns=default_scans.yml

Options:
  --project-name     Name for the project (required)
  --scope            Files containing target IP addresses or FQDNs (required, path)
  --exclude          File listing IPs/FQDNs to exclude from scans (path)
  --output           Output folder (defaults to stdout)
  --scan-patterns    YML file containing scan patterns
  --batch-size       Number of hosts to add to Nmap batches
  --debug-workers    Add print statements for worker output and include file/line info in logs
  --log-file         Path to log file or directory for logging all output (optional)

Notes:
  - Scope and exclude files should contain one IP/FQDN per line.
  - The --scan-patterns YAML file allows customization of Nmap options (e.g., ports, scan types).
  - Use --discover to filter unresponsive hosts, which may optimize scan time.
  - Ensure the output directory exists and is writable when using --output.
  - If --log-file points to a directory, a timestamped log file will be created automatically.
  - Log output is written to both stdout and the log file when --log-file is specified.
`
}
