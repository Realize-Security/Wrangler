package models

import "strings"

type ServiceAlias struct {
	Service string   `yaml:"service"`
	Aliases []string `yaml:"aliases"`
}

type ServiceAliasConfig struct {
	Aliases []ServiceAlias
}

type ServiceAliasManager struct {
	AliasMap   map[string]string
	ServiceMap map[string][]string
}

// IsServiceMatch checks if the detected service matches any of the target services
func (sam *ServiceAliasManager) IsServiceMatch(detectedService string, targetServices []string) bool {
	if len(targetServices) == 0 {
		return false
	}

	detected := strings.ToLower(detectedService)

	// Get canonical service for the detected service (if it's an alias)
	canonicalDetected, exists := sam.AliasMap[detected]
	if !exists {
		canonicalDetected = detected
	}

	// Check if any target service matches
	for _, target := range targetServices {
		targetLower := strings.ToLower(target)

		// Check if target is the canonical name of what we detected
		if targetLower == canonicalDetected {
			return true
		}

		// Check if target's canonical name matches our detected service's canonical name
		if canonicalTarget, exists := sam.AliasMap[targetLower]; exists {
			if canonicalTarget == canonicalDetected {
				return true
			}
		}

		// Check if the detected service is in the aliases for the target
		if aliases, exists := sam.ServiceMap[targetLower]; exists {
			for _, alias := range aliases {
				if alias == detected {
					return true
				}
			}
		}
	}

	return false
}
