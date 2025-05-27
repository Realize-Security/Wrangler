package models

import (
	"regexp"
	"strings"
)

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
	if len(targetServices) == 0 || detectedService == "" {
		return false
	}

	detected := strings.ToLower(detectedService)

	// Check if any target service matches
	for _, target := range targetServices {
		targetLower := strings.ToLower(target)

		// Check if detected service starts with target name
		pattern := "^" + regexp.QuoteMeta(targetLower)
		match, _ := regexp.MatchString(pattern, detected)
		if match {
			return true
		}

		// Check if detected service starts with any alias of the target
		if aliases, exists := sam.ServiceMap[targetLower]; exists {
			for _, alias := range aliases {
				aliasLower := strings.ToLower(alias)
				pattern := "^" + regexp.QuoteMeta(aliasLower)
				match, _ := regexp.MatchString(pattern, detected)
				if match {
					return true
				}
			}
		}

		// Check if detected service is an alias, and its canonical form starts with target
		if canonicalDetected, exists := sam.AliasMap[detected]; exists {
			pattern := "^" + regexp.QuoteMeta(targetLower)
			match, _ := regexp.MatchString(pattern, canonicalDetected)
			if match {
				return true
			}
		}
	}
	return false
}
