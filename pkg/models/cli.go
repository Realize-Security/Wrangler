package models

type CLI struct {
	ProjectName  string `name:"project-name" help:"Name for the project" required:""`
	ScopeFiles   string `name:"scope" help:"Files containing target IP addresses or FQDNs" required:"" type:"path"`
	ScopeExclude string `name:"exclude" help:"Exclude scope file from scans" type:"path"`
	Output       string `name:"output" help:"Output folder (defaults to stdout)"`
	PatternFile  string `name:"scan-patterns" help:"YML file containing scan patterns"`
	BatchSize    int    `name:"batch-size" help:"Number of hosts to add to Nmap batches"`
	DebugWorkers bool   `name:"debug-workers" help:"Add print statements for worker output"`
	LogFile      string `kong:"name='log-file',help='Path to log file or directory for logging all output'"`
}
