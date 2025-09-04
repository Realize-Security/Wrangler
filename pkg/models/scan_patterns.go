package models

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type ScanType string

type ScanConfig struct {
	Scans []ScanItem `yaml:"scan-collection"`
}

type ScanItem struct {
	ScanItem Scan `yaml:"scan-item"`
}

// Scan represents a scan configuration
type Scan struct {
	Tool             string   `yaml:"tool"`
	Protocol         string   `yaml:"protocol"`
	Args             []string `yaml:"args"`
	TargetService    []string `yaml:"services"`
	Description      string   `yaml:"description"`
	HostDiscovery    bool     `yaml:"host_discovery"`
	ServiceDiscovery bool     `yaml:"service_discovery"`
	ScopeArg         string
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for Scan
func (s *Scan) UnmarshalYAML(value *yaml.Node) error {
	// Try to decode as a struct with args as interface{}
	var temp struct {
		Tool             string      `yaml:"tool"`
		Protocol         string      `yaml:"protocol"`
		ArgsRaw          interface{} `yaml:"args"`
		TargetService    []string    `yaml:"services"`
		Description      string      `yaml:"description"`
		HostDiscovery    bool        `yaml:"host_discovery"`
		ServiceDiscovery bool        `yaml:"service_discovery"`
	}

	if err := value.Decode(&temp); err != nil {
		return err
	}

	// Copy regular fields
	s.Tool = temp.Tool
	s.Protocol = temp.Protocol
	s.TargetService = temp.TargetService
	s.Description = temp.Description
	s.HostDiscovery = temp.HostDiscovery
	s.ServiceDiscovery = temp.ServiceDiscovery

	// Process args based on type
	switch args := temp.ArgsRaw.(type) {
	case string:
		s.Args = parseArgs(args)
	case []interface{}:
		s.Args = flattenArgs(args)
	default:
		s.Args = []string{}
	}

	return nil
}

// flattenArgs recursively flattens nested arrays and parses strings
func flattenArgs(args []interface{}) []string {
	var result []string

	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			result = append(result, parseArgs(v)...)
		case []interface{}:
			result = append(result, flattenArgs(v)...)
		}
	}

	return result
}

// parseArgs intelligently splits argument strings
func parseArgs(argsStr string) []string {
	var args []string

	// Trim whitespace
	argsStr = strings.TrimSpace(argsStr)
	if argsStr == "" {
		return args
	}

	// Regular expression to match either:
	// 1. Single quoted strings (preserving content)
	// 2. Double-quoted strings (preserving content)
	// 3. Non-whitespace sequences
	re := regexp.MustCompile(`'[^']*'|"[^"]*"|\S+`)

	matches := re.FindAllString(argsStr, -1)

	for _, match := range matches {
		// Remove surrounding quotes if present, but keep the content intact
		if (strings.HasPrefix(match, "'") && strings.HasSuffix(match, "'")) ||
			(strings.HasPrefix(match, `"`) && strings.HasSuffix(match, `"`)) {
			// Remove quotes but keep the content as a single argument
			args = append(args, match[1:len(match)-1])
		} else {
			args = append(args, match)
		}
	}

	return args
}
