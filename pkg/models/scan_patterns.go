package models

import "gopkg.in/yaml.v3"

type ScanType string

type ScanConfig struct {
	Scans []ScanItem `yaml:"scan-collection"`
}

type ScanItem struct {
	ScanItem Scan `yaml:"scan-item"`
}

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

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (s *Scan) UnmarshalYAML(value *yaml.Node) error {
	// Create a temporary struct for unmarshaling
	var temp struct {
		Tool             string    `yaml:"tool"`
		Protocol         string    `yaml:"protocol"`
		TargetService    []string  `yaml:"services"`
		Description      string    `yaml:"description"`
		HostDiscovery    bool      `yaml:"host_discovery"`
		ServiceDiscovery bool      `yaml:"service_discovery"`
		ArgsRaw          yaml.Node `yaml:"args"`
	}

	// Unmarshal into the temporary struct
	if err := value.Decode(&temp); err != nil {
		return err
	}

	// Copy the regular fields
	s.Tool = temp.Tool
	s.Protocol = temp.Protocol
	s.TargetService = temp.TargetService
	s.Description = temp.Description
	s.HostDiscovery = temp.HostDiscovery
	s.ServiceDiscovery = temp.ServiceDiscovery

	// Process the args field specially
	var flattenArgs []string
	if temp.ArgsRaw.Kind == yaml.SequenceNode {
		flattenArgs = flattenSequence(temp.ArgsRaw.Content)
	}
	s.Args = flattenArgs

	return nil
}

// Helper function to flatten nested sequences
func flattenSequence(nodes []*yaml.Node) []string {
	var result []string

	for _, node := range nodes {
		// If this node is a sequence, recursively flatten it
		if node.Kind == yaml.SequenceNode {
			result = append(result, flattenSequence(node.Content)...)
			continue
		}

		// Otherwise, treat it as a string
		var str string
		if err := node.Decode(&str); err == nil {
			result = append(result, str)
		}
	}

	return result
}
