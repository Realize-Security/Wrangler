package models

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
