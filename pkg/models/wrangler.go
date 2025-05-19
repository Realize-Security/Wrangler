package models

import (
	"context"
	"github.com/google/uuid"
	"os/exec"
	"time"
)

type Project struct {
	ExecutionID       uuid.UUID
	Name              string `validate:"required"`
	InScopeFile       string `validate:"required"`
	ExcludeScopeFile  string `validate:"required"`
	ReportDirParent   string `validate:"required"`
	ProjectReportPath string
	ProjectBase       string
	TempPrefix        string
	InScopeHosts      []string
}

type Target struct {
	Host  string
	Ports []NmapPort
}

// Worker describes a single worker’s configuration and runtime state.
type Worker struct {
	ID            uuid.UUID
	Tool          string
	Args          []string
	Protocol      string
	Target        string
	TargetService []string
	Description   string
	XMLReportPath string
	ScopeArg      string

	// SubTypes
	IsHostDiscovery    bool
	IsServiceDiscovery bool

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
