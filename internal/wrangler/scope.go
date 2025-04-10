package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/helpers"
	"fmt"
	"os"
	"strings"
)

// FlattenScopes flattens IP addresses, FQDNs and CIDRs into individual IP addresses
func (wr *wranglerRepository) FlattenScopes(paths string) ([]string, error) {
	rawScopes := strings.Split(paths, ",")
	scopes := make([]string, 0, len(rawScopes))
	for _, s := range rawScopes {
		s = strings.TrimSpace(s)
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("no scopes specified")
	}

	for _, scope := range scopes {
		if _, err := os.Stat(scope); os.IsNotExist(err) {
			return nil, fmt.Errorf("file %s does not exist", scope)
		}
	}

	uniqueIPs := make(map[string]struct{})

	for _, scope := range scopes {
		lines, err := files.FileLinesToSlice(scope)
		if err != nil {
			return nil, fmt.Errorf("unable to parse file %s: %v", scope, err)
		}
		for _, line := range lines {
			expanded := expandCIDR(line)

			if len(expanded) == 0 {
				uniqueIPs[line] = struct{}{}
				continue
			}

			for _, ip := range expanded {
				uniqueIPs[ip] = struct{}{}
			}
		}
	}

	if len(uniqueIPs) == 0 {
		return nil, fmt.Errorf("empty target set")
	}

	final := make([]string, 0, len(uniqueIPs))
	for ip := range uniqueIPs {
		final = append(final, ip)
	}

	if err := helpers.ValidateScope(final); err != nil {
		return nil, err
	}
	return final, nil
}

func expandCIDR(cidr string) []string {
	finalIps := make([]string, 0)
	res := helpers.ParseIPV4CIDR(cidr)
	if res != nil {
		finalIps = append(finalIps, res...)
	} else {
		finalIps = append(finalIps, cidr)
	}
	return finalIps
}
