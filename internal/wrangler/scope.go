package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/validators"
	"fmt"
	"os"
	"strings"
)

func (wr *wranglerRepository) FlattenScopes(paths string) ([]string, error) {
	scopes := strings.Split(paths, ",")
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if _, err := os.Stat(scope); os.IsNotExist(err) {
			return nil, fmt.Errorf("file %s does not exist", scope)
		}
	}
	var allIps []string

	for _, scope := range scopes {
		ips, err := files.FileLinesToSlice(scope)
		if err != nil {
			return nil, fmt.Errorf("unable to parse: %s. error: %s", scope, err.Error())
		}
		allIps = append(allIps, ips...)
	}

	ipLen := len(allIps)
	final := make([]string, 0, ipLen)
	uniqueIps := make(map[string]bool, ipLen)

	for _, ip := range allIps {
		if !uniqueIps[ip] {
			uniqueIps[ip] = true
			final = append(final, ip)
		}
	}

	if err := validators.ValidateScope(final); err != nil {
		return nil, err
	}
	return final, nil
}
