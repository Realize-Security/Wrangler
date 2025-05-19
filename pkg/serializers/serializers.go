package serializers

import (
	"Wrangler/pkg/models"
	"gopkg.in/yaml.v3"
	"os"
)

func LoadScansFromYAML(filePath string) ([]models.Scan, *models.ServiceAliasConfig, []models.ScopeAssignment, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, err
	}
	var config struct {
		ServiceAliases  []models.ServiceAlias    `yaml:"service-aliases"`
		ScopeAssignment []models.ScopeAssignment `yaml:"scope-assignment"`
		Scans           []struct {
			ScanItem models.Scan `yaml:"scan-item"`
		} `yaml:"scan-collection"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, nil, nil, err
	}
	scans := make([]models.Scan, 0, len(config.Scans))
	for _, item := range config.Scans {
		scans = append(scans, item.ScanItem)
	}
	serviceConfig := &models.ServiceAliasConfig{
		Aliases: config.ServiceAliases,
	}
	return scans, serviceConfig, config.ScopeAssignment, nil
}
