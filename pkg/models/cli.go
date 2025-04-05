package models

type CLI struct {
	ProjectName  string `name:"project-name" help:"Name for the project" required:""`
	ScopeFiles   string `name:"scope" help:"Files containing target IP addresses or FQDNs" required:"" type:"path"`
	NonRootUser  string `name:"non-root-user" help:"Non-root user who will own report files." required:""`
	ScopeExclude string `name:"exclude" help:"ExcludeScopeFile from scans" type:"path"`
	Output       string `name:"output" help:"Output folder (defaults to stdout)"`
	PatternFile  string `name:"scan-patterns" help:"YML file containing scan patterns"`
	//BatchSize    string `name:"batch-size" help:"Number of hosts to add to Nmap batches" required:""`
	RunDiscovery bool `name:"discover" help:"Run ICMP and port knocking checks to establish host availability"`
}
