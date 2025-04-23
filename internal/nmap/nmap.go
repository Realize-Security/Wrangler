package nmap

import (
	"Wrangler/pkg/models"
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
)

var (
	VerbosityLow    = "-v"
	VerbosityMedium = "-vv"
	VerbosityHigh   = "-vvv"
)

const (
	TCP        = "tcp"
	UDP        = "udp"
	TCPandUDP  = "both"
	SYN        = "ss"
	NoPorts    = "sn"
	Paranoid   = "0"
	Sneaky     = "1"
	Polite     = "2"
	Normal     = "3"
	Aggressive = "4"
	Insane     = "5"
)

// Command holds the scan type, targets, and a map of arguments
type Command struct {
	ScanType string
	Targets  string
	Args     map[string]string
}

// Add is a builder for adding arguments to a Command
type Add struct {
	cmd *Command
}

// ToArgList converts the Command to a slice of argument strings in the format "--key value" or "key" for flags
func (c *Command) ToArgList() []string {
	var args []string
	for key, value := range c.Args {
		if value == "" {
			args = append(args, key)
		} else {
			args = append(args, key, value)
		}
	}
	return args
}

// Add returns an Add builder for configuring arguments
func (c *Command) Add() *Add {
	return &Add{cmd: c}
}

// TopPorts sets the top-ports argument
func (a *Add) TopPorts(value int) *Add {
	a.cmd.Args["--top-ports"] = strconv.Itoa(value)
	return a
}

// MinHostGroup sets the min-hostgroup argument
func (a *Add) MinHostGroup(value int) *Add {
	a.cmd.Args["--min-hostgroup"] = strconv.Itoa(value)
	return a
}

// MinRTTTimeout sets the min-rtt-timeout argument
func (a *Add) MinRTTTimeout(value string) *Add {
	a.cmd.Args["--min-rtt-timeout"] = value
	return a
}

// MaxRetries sets the max-retries argument
func (a *Add) MaxRetries(value int) *Add {
	a.cmd.Args["--max-retries"] = strconv.Itoa(value)
	return a
}

// HostTimeout sets the host-timeout argument
func (a *Add) HostTimeout(value string) *Add {
	a.cmd.Args["--host-timeout"] = value
	return a
}

// ScriptTimeout sets the script-timeout argument
func (a *Add) ScriptTimeout(value string) *Add {
	a.cmd.Args["--script-timeout"] = value
	return a
}

// MinRate sets the min-rate argument
func (a *Add) MinRate(value int) *Add {
	a.cmd.Args["--min-rate"] = strconv.Itoa(value)
	return a
}

// ExcludeFile sets the exclude-file argument
func (a *Add) ExcludeFile(value string) *Add {
	a.cmd.Args["--excludefile"] = value
	return a
}

// InputFile sets the input-file argument
func (a *Add) InputFile(value string) *Add {
	a.cmd.Args["-iL"] = value
	return a
}

// OutputAll sets the -oA argument
func (a *Add) OutputAll(value string) *Add {
	a.cmd.Args["-oA"] = value
	return a
}

// Verbose sets the verbosity level
func (a *Add) Verbose(level string) *Add {
	a.cmd.Args[level] = ""
	return a
}

// NoResolve sets the -n argument
func (a *Add) NoResolve() *Add {
	a.cmd.Args["-n"] = ""
	return a
}

// PerformanceTemplate sets the -T argument with a value from 0 to 5
func (a *Add) PerformanceTemplate(value string) *Add {
	iv, err := strconv.Atoi(value)
	if err != nil || (iv > 5 || iv < 0) {
		e := fmt.Errorf("%s is not a valid argument for Nmap timing templates", value)
		panic(e)
	}

	a.cmd.Args["-T"] = value
	return a
}

// Custom adds a custom key-value pair
func (a *Add) Custom(key, value string) *Add {
	a.cmd.Args[key] = value
	return a
}

// NewCommand creates a new Command with default arguments
func NewCommand(scanType, targets string, customArgs map[string]string) *Command {
	// Default arguments
	defaultArgs := make(map[string]string)

	// Apply scan-type flags
	switch scanType {
	case TCP:
		defaultArgs["-sT"] = ""
	case UDP:
		defaultArgs["-sU"] = ""
	case TCPandUDP:
		defaultArgs["-sTU"] = ""
	case SYN:
		defaultArgs["-sS"] = ""
	case NoPorts:
		defaultArgs["-sn"] = ""
	}

	// Create Args map by merging defaults with custom arguments
	args := make(map[string]string)
	for key, value := range defaultArgs {
		args[key] = value
	}
	for key, value := range customArgs {
		args[key] = value // Override defaults with custom values
	}

	return &Command{
		ScanType: scanType,
		Targets:  targets,
		Args:     args,
	}
}

// ReadNmapXML returns a pointer to models.NmapRun
func ReadNmapXML(nmapFile string) (*models.NmapRun, error) {
	f, err := os.Open(nmapFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var result models.NmapRun
	if err := xml.NewDecoder(f).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
