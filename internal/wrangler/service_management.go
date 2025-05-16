package wrangler

import (
	"Wrangler/pkg/models"
	"strings"
)

func NewServiceAliasManager(aliases []models.ServiceAlias) *models.ServiceAliasManager {
	manager := &models.ServiceAliasManager{
		AliasMap:   make(map[string]string),
		ServiceMap: make(map[string][]string),
	}

	for _, alias := range aliases {
		service := strings.ToLower(alias.Service)
		// Add the service name as its own alias
		manager.AliasMap[service] = service
		manager.ServiceMap[service] = append(manager.ServiceMap[service], service)

		// Add all aliases for this service
		for _, aliasName := range alias.Aliases {
			aliasLower := strings.ToLower(aliasName)
			manager.AliasMap[aliasLower] = service
			manager.ServiceMap[service] = append(manager.ServiceMap[service], aliasLower)
		}
	}
	return manager
}
