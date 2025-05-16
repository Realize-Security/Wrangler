package serializers

import (
	"Wrangler/pkg/models"
	"gopkg.in/yaml.v3"
	"os"
)

func LoadScansFromYAML(filePath string) ([]models.ScanDetails, *models.ServiceAliasConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	var config struct {
		ServiceAliases []models.ServiceAlias `yaml:"service-aliases"`
		Scans          []struct {
			ScanItem models.ScanDetails `yaml:"scan-item"`
		} `yaml:"scan-collection"`
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, nil, err
	}

	scans := make([]models.ScanDetails, 0, len(config.Scans))
	for _, item := range config.Scans {
		scans = append(scans, item.ScanItem)
	}

	serviceConfig := &models.ServiceAliasConfig{
		Aliases: config.ServiceAliases,
	}
	return scans, serviceConfig, nil
}
