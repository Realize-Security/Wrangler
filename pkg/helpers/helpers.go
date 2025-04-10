package helpers

import (
	"encoding/binary"
	"net"
	"strings"
)

func SpacesToUnderscores(description string) string {
	description = strings.ToLower(description)
	return strings.Replace(description, " ", "_", -1)
}

// ParseIPV4CIDR checks is s scope item is s CIDR. If true it returns all addresses in range.
// If false, empty []string is returned
func ParseIPV4CIDR(cidr string) (result []string) {
	ipv4Net := IPv4IsCIDR(cidr)
	if ipv4Net == nil {
		return result
	}

	// convert IPNet struct mask and address to uint32
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	// find the final address
	finish := (start & mask) | (mask ^ 0xffffffff)

	// loop through addresses as uint32
	for i := start; i <= finish; i++ {
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		result = append(result, ip.String())
	}
	return
}

// IPv4IsCIDR check if a string value is a valid IPv4 CIDR. Returns *net.IPNet if true.
func IPv4IsCIDR(ip string) *net.IPNet {
	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(ip)
	if err != nil {
		return nil
	}
	return ipv4Net
}
