package helpers

import "strings"

func SpacesToUnderscores(description string) string {
	description = strings.ToLower(description)
	return strings.Replace(description, " ", "_", -1)
}
