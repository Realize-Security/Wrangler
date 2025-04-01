package models

type ScanType string

type ScanConfig struct {
	Scans []ScanItem `yaml:"scan-collection"`
}

type ScanItem struct {
	ScanItem ScanDetails `yaml:"scan-item"`
}

type ScanDetails struct {
	Tool        string   `yaml:"tool"`
	Args        []string `yaml:"args"`
	Description string   `yaml:"description"`
}
