package models

type ScanType string

type ScanConfig struct {
	Scans []ScanItem `yaml:"scan-collection"`
}

type ScanItem struct {
	ScanItem ScanDetails `yaml:"scan-item"`
}

type ScanDetails struct {
	Tool          string   `yaml:"tool"`
	Protocol      string   `yaml:"protocol"`
	Args          []string `yaml:"args"`
	TargetService string   `yaml:"service"`
	Description   string   `yaml:"description"`
}
