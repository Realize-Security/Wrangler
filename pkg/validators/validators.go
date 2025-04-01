package validators

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func ValidateScope(scope []string) error {
	for _, target := range scope {
		if !IsValidScopeItem(target) {
			return fmt.Errorf("not a valid IP, CIDR or URL: %s", target)
		}
	}
	return nil
}

// IsValidScopeItem returns true if str is a valid IP, CIDR, or bare host:port.
func IsValidScopeItem(str string) bool {
	// Try each validator
	if ValidateIP(str) {
		return true
	}
	if ValidateCIDR(str) {
		return true
	}
	if ValidateBareURL(str) {
		return true
	}
	return false
}

// ValidateIP returns true if addr is a valid IPv4 or IPv6 address.
func ValidateIP(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil
}

// ValidateCIDR returns true if cidr is in valid CIDR notation, like "192.168.0.0/24".
func ValidateCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// ValidateBareURL ensures a string is just a host (domain or IP) plus optional port.
// It rejects any scheme (e.g. "http://") or path (e.g. "/some/path").
// Examples of valid strings: "example.com", "example.com:8080", "192.168.1.10", "localhost".
func ValidateBareURL(hostPort string) bool {
	// Quick checks for obvious path or scheme indicators
	if strings.Contains(hostPort, "/") || strings.Contains(hostPort, "//") {
		return false
	}

	// Use a trick: prefix with "//" so net/url parses hostPort as the Host field.
	// Example: hostPort = "example.com:8080" => url.Parse("//example.com:8080")
	u, err := url.Parse("//" + hostPort)
	if err != nil {
		return false
	}

	// Must have empty scheme, path, query, fragment, etc.
	if u.Scheme != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	// u.Host should not be empty
	if u.Host == "" {
		return false
	}

	// net/url includes the port in u.Host if present, e.g. "example.com:8080".
	// Let's separate them to validate properly.
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		// Means there was no colon/port, so the entire thing is considered host
		host = u.Host
	} else {
		u.Host = host
	}

	// If host is empty, invalid
	if host == "" {
		return false
	}

	// Check if host is a valid IP. If nil, assume it's a domain name or "localhost".
	// Minimal domain check: if not an IP, ensure there's at least one '.' (except "localhost").
	if net.ParseIP(host) == nil {
		if host != "localhost" && !strings.Contains(host, ".") {
			return false
		}
	}
	return true
}
