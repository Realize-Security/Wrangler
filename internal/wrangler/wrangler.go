package wrangler

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"
)

// workerStop is the command used to tell the worker goroutine to exit.
const WorkerStop = "STOP"

// Project holds overall info, plus a slice of Workers we want to run.
type Project struct {
	ID               int
	Name             string `validate:"required"`
	InScopeFile      string `validate:"required"`
	ExcludeScopeFile string `validate:"required"`
	ReportDir        string `validate:"required"`
	Workers          []Worker
}

// Worker describes a single worker’s configuration and runtime state.
type Worker struct {
	ID          int
	Type        string `validate:"required"`
	Command     string `validate:"required"`
	Args        []string
	Description string `validate:"required"`
	Started     time.Time
	Finished    time.Time
	CancelFunc  context.CancelFunc

	UserCommand    chan string
	WorkerResponse chan string
}

// WranglerRepository defines the interface for creating and managing Projects.
type WranglerRepository interface {
	NewProject(name, inScope, excludeScope, reportDir string) *Project
	ProjectInit(project *Project)
	StartWorkers(project *Project) *sync.WaitGroup
	reportName(description string) string
}

type wranglerRepository struct{}

// NewWranglerRepository constructs our repository.
func NewWranglerRepository() WranglerRepository {
	return &wranglerRepository{}
}

// NewProject creates a new Project (not yet started).
func (wr *wranglerRepository) NewProject(name, inScope, excludeScope, reportDir string) *Project {
	return &Project{
		Name:             name,
		InScopeFile:      inScope,
		ExcludeScopeFile: excludeScope,
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

// StartWorkers spins up all workers in goroutines. Each worker listens for commands
// on its UserCommand channel and sends results on its WorkerResponse channel.
func (wr *wranglerRepository) StartWorkers(project *Project) *sync.WaitGroup {
	var wg sync.WaitGroup

	for i := range project.Workers {
		wg.Add(1)
		w := &project.Workers[i]
		// Add additional tool arguments
		w.Args = append(w.Args, "-T4")

		w.Args = append(w.Args, "-iL")
		w.Args = append(w.Args, project.InScopeFile)

		if project.ExcludeScopeFile != "" {
			w.Args = append(w.Args, "--excludefile")
			w.Args = append(w.Args, project.ExcludeScopeFile)
		}

		reportName := wr.reportName(w.Description)
		workerReport := path.Join(project.ReportDir, reportName)
		w.Args = append(w.Args, "-oA")
		w.Args = append(w.Args, workerReport)

		go worker(w, &wg)
		w.UserCommand <- "run"
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
		output, err := runCommand(ctx, wk.Command, wk.Args)

		if err != nil {
			wk.WorkerResponse <- fmt.Sprintf("Worker %d error: %v\nOutput:\n%s", wk.ID, err, output)
		} else {
			wk.WorkerResponse <- fmt.Sprintf("Worker %d completed.\nOutput:\n%s", wk.ID, output)
		}
	}
}

// runCommand is a helper to execute an external command with the given args
// and return combined stdout/stderr.
func runCommand(ctx context.Context, cmdName string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, cmdName, args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	return out.String(), err
}

func (wr *wranglerRepository) reportName(description string) string {
	description = strings.ToLower(description)
	return strings.Replace(description, " ", "_", -1)
}
