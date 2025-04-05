package wrangler

import (
	"Wrangler/pkg/helpers"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path"
	"strconv"
	"sync"
	"time"
)

// workerStop is the command used to tell the worker goroutine to exit.
const WorkerStop = "STOP"

var (
	// TCPTimeoutMins TCP discovery scans will exist after n minutes
	TCPTimeoutMins = 5 * time.Minute

	// UDPTimeoutMins UDP discovery scans will exist after n minutes
	UDPTimeoutMins = 10 * time.Minute
)

// Project holds overall info, plus a slice of Workers we want to run.
type Project struct {
	ID               int
	Name             string `validate:"required"`
	InScopeFile      string `validate:"required"`
	ExcludeScopeFile string `validate:"required"`
	ReportDir        string `validate:"required"`
	Targets          []Target
	Workers          []Worker
}

type Target struct {
	Target    string `validate:"required"`
	OpenPorts []int
}

type defaultProtoCols struct {
	TCP string
	UDP string
}

// Worker describes a single worker’s configuration and runtime state.
type Worker struct {
	ID             int
	Type           string `validate:"required"`
	Command        string `validate:"required"`
	Args           []string
	Target         string
	Description    string `validate:"required"`
	Started        time.Time
	Finished       time.Time
	Timeout        time.Duration
	CancelFunc     context.CancelFunc
	UserCommand    chan string
	WorkerResponse chan string
	ErrorChan      chan error
}

// WranglerRepository defines the interface for creating and managing Projects.
type WranglerRepository interface {
	NewProject(name, excludeScope, reportDir string) *Project
	ProjectInit(project *Project)
	HostDiscoveryScan(workers []Worker, exclude string) *sync.WaitGroup
	PortOpenOrClosedDiscovery(project *Project, targets []string, protocol string, topPorts int) (*sync.WaitGroup, error)
	StartWorkers(project *Project, fullScan <-chan string, batchSize int) *sync.WaitGroup
}

type wranglerRepository struct{}

// NewWranglerRepository constructs our repository.
func NewWranglerRepository() WranglerRepository {
	return &wranglerRepository{}
}

// NewProject creates a new Project (not yet started).
func (wr *wranglerRepository) NewProject(name, excludeScope, reportDir string) *Project {
	return &Project{
		Name:             name,
		ExcludeScopeFile: excludeScope,
		ReportDir:        reportDir,
	}
}

// ProjectInit initializes each Worker’s channels but does NOT start them yet.
func (wr *wranglerRepository) ProjectInit(project *Project) {
	for i, wk := range project.Workers {
		wk.UserCommand = make(chan string)
		wk.WorkerResponse = make(chan string)
		project.Workers[i] = wk
	}
}

// HostDiscoveryScan initiates ICMP and port check discovery.
// This runs one nmap -sn scan per host.
func (wr *wranglerRepository) HostDiscoveryScan(workers []Worker, exclude string) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		w := &workers[i]
		w.Command = "nmap"
		if exclude != "" {
			w.Args = append(w.Args, "--excludefile")
			w.Args = append(w.Args, exclude)
		}
		// Only initialize if not set (optional safety)
		if w.UserCommand == nil {
			w.UserCommand = make(chan string, 1)
		}
		if w.WorkerResponse == nil {
			w.WorkerResponse = make(chan string)
		}
		if w.ErrorChan == nil {
			w.ErrorChan = make(chan error)
		}
		go worker(w, &wg)
		w.UserCommand <- "run"
	}
	return &wg
}

// PortOpenOrClosedDiscovery checks for at least one TCP or UDP port being open or closed
func (wr *wranglerRepository) PortOpenOrClosedDiscovery(project *Project, targets []string, protocol string, topPorts int) (*sync.WaitGroup, error) {
	var wg sync.WaitGroup
	protocols := map[string]string{"tcp": "-sT", "udp": "-sU"}

	for i, target := range targets {
		wg.Add(1)

		proto, ok := protocols[protocol]
		if !ok {
			return nil, fmt.Errorf("%s is a not a valid protocol. Use 'tcp' or 'udp'", protocol)
		}

		w := &Worker{
			ID:     i,
			Type:   "nmap",
			Target: target,
			Args:   []string{proto, target},
		}

		var portLimit string
		if proto == "tcp" {
			w.Timeout = TCPTimeoutMins
			portLimit = strconv.Itoa(topPorts)
		} else {
			w.Timeout = UDPTimeoutMins
			portLimit = strconv.Itoa(topPorts)
		}

		portArgs := []string{"--top-ports", portLimit}
		w.Args = append(w.Args, portArgs...)

		if project.ExcludeScopeFile != "" {
			w.Args = append(w.Args, "--excludefile")
			w.Args = append(w.Args, project.ExcludeScopeFile)
		}

		w.UserCommand = make(chan string, 1)
		w.WorkerResponse = make(chan string)
		w.ErrorChan = make(chan error)

		go worker(w, &wg)
		w.UserCommand <- "run"
	}
	return &wg, nil
}

// StartWorkers spins up all workers in goroutines. Each worker listens for commands
// on its UserCommand channel and sends results on its WorkerResponse channel.
func (wr *wranglerRepository) StartWorkers(p *Project, fullScan <-chan string, size int) *sync.WaitGroup {
	var wg sync.WaitGroup

	for {
		batch := helpers.ReadNTargetsFromChannel(fullScan, size)
		if len(batch) == 0 {
			break
		}

		for i := range p.Workers {
			wg.Add(1)
			w := &p.Workers[i]
			// Add additional tool arguments
			w.Args = append(w.Args, "-T4")

			w.Args = append(w.Args, "-iL")
			w.Args = append(w.Args, p.InScopeFile)

			if p.ExcludeScopeFile != "" {
				w.Args = append(w.Args, "--excludefile")
				w.Args = append(w.Args, p.ExcludeScopeFile)
			}

			reportName := helpers.SpacesToUnderscores(w.Description)
			workerReport := path.Join(p.ReportDir, reportName)
			w.Args = append(w.Args, "-oA")
			w.Args = append(w.Args, workerReport)

			go worker(w, &wg)
			w.UserCommand <- "run"
		}
	}
	return &wg
}

// worker continuously reads from worker.UserCommand, runs the external command
// (or does other long-running tasks), and sends results back on worker.WorkerResponse.
func worker(wk *Worker, wg *sync.WaitGroup) {
	defer wg.Done()
	wk.Started = time.Now()

	for {
		cmd, ok := <-wk.UserCommand
		if !ok {
			wk.Finished = time.Now()
			wk.WorkerResponse <- fmt.Sprintf("Worker %d: commands channel closed, stopping.", wk.ID)
			return
		}

		if cmd == WorkerStop {
			if wk.CancelFunc != nil {
				wk.CancelFunc()
			}
			wk.Finished = time.Now()
			wk.WorkerResponse <- fmt.Sprintf("Worker %d: STOP command received, shutting down.", wk.ID)
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		wk.CancelFunc = cancel

		output, err := runCommandCtx(ctx, wk.Command, wk.Args)
		wk.WorkerResponse <- output

		if err != nil {
			wk.ErrorChan <- err
		} else {
			wk.ErrorChan <- nil
		}
		close(wk.ErrorChan)
	}
}

// runCommandCtx is a helper to execute an external command with the given args
// and return combined stdout/stderr.
func runCommandCtx(ctx context.Context, cmdName string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, cmdName, args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	return out.String(), err
}
