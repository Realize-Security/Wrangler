package wrangler

import (
	"bytes"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// workerStop is the command used to tell the worker goroutine to exit.
const workerStop = "STOP"

// Project holds overall info, plus a slice of Workers we want to run.
type Project struct {
	ID      int
	Name    string   `validate:"required"`
	Scope   []string `validate:"required"`
	Exclude []string `validate:"required"`
	Workers []Worker
}

// Worker describes a single worker’s configuration and runtime state.
type Worker struct {
	ID       int
	Type     string `validate:"required"`
	Command  string `validate:"required"`
	Args     []string
	Started  time.Time
	Finished time.Time

	Commands  chan string
	Responses chan string
}

// WranglerRepository defines the interface for creating and managing Projects.
type WranglerRepository interface {
	NewProject(name string, scope, exclude []string) *Project
	ProjectInit(project *Project)
	StartWorkers(project *Project) *sync.WaitGroup
}

type wranglerRepository struct{}

// NewWranglerRepository constructs our repository.
func NewWranglerRepository() WranglerRepository {
	return &wranglerRepository{}
}

// NewProject creates a new Project (not yet started).
func (wr *wranglerRepository) NewProject(name string, scope, exclude []string) *Project {
	return &Project{
		Name:    name,
		Scope:   scope,
		Exclude: exclude,
	}
}

// ProjectInit initializes each Worker’s channels but does NOT start them yet.
func (wr *wranglerRepository) ProjectInit(project *Project) {
	for i, wk := range project.Workers {
		wk.Commands = make(chan string)
		wk.Responses = make(chan string)
		project.Workers[i] = wk
	}
}

// StartWorkers spins up all workers in goroutines. Each worker listens for commands
// on its Commands channel and sends results on its Responses channel.
func (wr *wranglerRepository) StartWorkers(project *Project) *sync.WaitGroup {
	var wg sync.WaitGroup

	for i := range project.Workers {
		wg.Add(1)
		go worker(&project.Workers[i], &wg)
	}
	return &wg

	// Optionally, you can wait in the background until all finish
	// and then do something else (e.g. cleanup, logging, etc.).
	//go func() {
	//	wg.Wait()
	//	fmt.Println("All workers have stopped.")
	//}()
}

// worker continuously reads from worker.Commands, runs the external command
// (or does other long-running tasks), and sends results back on worker.Responses.
func worker(wk *Worker, wg *sync.WaitGroup) {
	defer wg.Done()
	wk.Started = time.Now()

	for {
		cmd, ok := <-wk.Commands
		if !ok {
			// Channel closed => time to stop
			wk.Finished = time.Now()
			wk.Responses <- fmt.Sprintf("Worker %d: commands channel closed, stopping.", wk.ID)
			return
		}

		if cmd == workerStop {
			wk.Finished = time.Now()
			wk.Responses <- fmt.Sprintf("Worker %d: STOP command received, shutting down.", wk.ID)
			return
		}

		output, err := runCommand(wk.Command, wk.Args)
		if err != nil {
			wk.Responses <- fmt.Sprintf("Worker %d error: %v\nOutput:\n%s", wk.ID, err, output)
		} else {
			wk.Responses <- fmt.Sprintf("Worker %d completed.\nOutput:\n%s", wk.ID, output)
		}
	}
}

// runCommand is a helper to execute an external command with the given args
// and return combined stdout/stderr.
func runCommand(cmdName string, args []string) (string, error) {
	cmd := exec.Command(cmdName, args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	return out.String(), err
}
