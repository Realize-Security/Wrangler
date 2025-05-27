package models

// ScopeAssignment represents scope assignment configuration
type ScopeAssignment struct {
	Tool        string `yaml:"tool"`
	Arg         string `yaml:"arg"`
	Description string `yaml:"description"`
}
