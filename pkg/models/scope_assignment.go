package models

type ScopeAssignment struct {
	Tool        string `yaml:"tool"`
	Arg         string `yaml:"arg"`
	Description string `yaml:"description"`
}
