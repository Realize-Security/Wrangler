package helpers

import (
	"strings"
)

func SpacesToUnderscores(description string) string {
	return strings.Replace(strings.ToLower(description), " ", "_", -1)
}

// ReadNFromSlice reads up to n values from a slice and returns them as a new slice.
// If the input slice has fewer than n elements, all available elements are returned.
func ReadNFromSlice[T any](slice []T, n int) []T {
	if n <= 0 {
		return []T{}
	}
	if len(slice) <= n {
		return slice
	}
	return slice[:n]
}
