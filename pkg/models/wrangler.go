package models

import (
	"context"
	"os/exec"
	"time"
)

type Project struct {
	ID               int
	Name             string `validate:"required"`
	InScopeFile      string `validate:"required"`
	ExcludeScopeFile string `validate:"required"`
	ReportDir        string `validate:"required"`
	Targets          []Target
	Workers          []Worker
	Cwd              string
	ReportPath       string
}

type Target struct {
	Host  string
	OS    string
	FQDN  string
	Ports []string
}

// Worker describes a single worker’s configuration and runtime state.
type Worker struct {
	ID            int
	Type          string
	Command       string
	Args          []string
	Target        string
	Description   string
	XMLReportPath string

	// Start/finish times and optional timeout
	Started    time.Time
	Finished   time.Time
	Timeout    time.Duration
	CancelFunc context.CancelFunc

	// Channels for commands, optional responses, and errors
	UserCommand    chan string
	WorkerResponse chan string
	ErrorChan      chan error
	XMLPathsChan   chan string

	// Store the final output & error from the external command
	Output   string
	Err      error
	StdError string

	// Store the exec.Cmd itself for SIGKILL if needed
	Cmd *exec.Cmd
}
