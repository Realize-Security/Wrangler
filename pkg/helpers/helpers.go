package helpers

import (
	"strings"
)

func SpacesToUnderscores(description string) string {
	return strings.Replace(strings.ToLower(description), " ", "_", -1)
}
