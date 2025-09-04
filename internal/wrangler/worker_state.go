package wrangler

import (
	"Wrangler/pkg/models"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// WorkerTracker tracks which workers have processed which target:port combinations across different project execution IDs
type WorkerTracker struct {
	store sync.Map // Maps string keys to bool values (existence is what matters)
}

// NewWorkerTracker creates a new WorkerTracker instance
func NewWorkerTracker() *WorkerTracker {
	return &WorkerTracker{
		store: sync.Map{},
	}
}

// Track records that a worker has processed a specific host:port
// This is thread-safe and can be called from multiple goroutines
func (wt *WorkerTracker) Track(execID uuid.UUID, host string, port string, protocol string, worker *models.Worker) {
	key := wt.createKey(execID, host, port, protocol, worker)
	wt.store.Store(key, true)
}

// IsTracked checks if a worker has already processed a specific host:port
// Returns true if already processed, false otherwise
// This is thread-safe and can be called from multiple goroutines
func (wt *WorkerTracker) IsTracked(execID uuid.UUID, host string, port string, protocol string, worker *models.Worker) bool {
	key := wt.createKey(execID, host, port, protocol, worker)
	_, exists := wt.store.Load(key)
	return exists
}

// createKey generates a unique string key for the worker/target combination
func (wt *WorkerTracker) createKey(execID uuid.UUID, host string, port string, protocol string, worker *models.Worker) string {
	// Create a worker signature that identifies what the worker does
	// This combines tool, description and target service (if any)
	workerSignature := fmt.Sprintf("%s:%s", worker.Tool, worker.Description)

	if len(worker.TargetService) > 0 {
		workerSignature += ":" + strings.Join(worker.TargetService, ",")
	}

	// Format: "execID:host:port:protocol:workerSignature"
	return fmt.Sprintf("%s:%s:%s:%s:%s",
		execID.String(),
		host,
		port,
		protocol,
		workerSignature)
}

// ClearProject removes all tracking data for a specific project execution ID
func (wt *WorkerTracker) ClearProject(execID uuid.UUID) {
	prefix := execID.String() + ":"

	// We need to collect keys first, then delete them
	var keysToDelete []string

	wt.store.Range(func(k, v interface{}) bool {
		key, ok := k.(string)
		if ok && strings.HasPrefix(key, prefix) {
			keysToDelete = append(keysToDelete, key)
		}
		return true
	})

	// Delete the collected keys
	for _, key := range keysToDelete {
		wt.store.Delete(key)
	}
}

// TrackForTarget is a convenience method for tracking all ports in a target
func (wt *WorkerTracker) TrackForTarget(execID uuid.UUID, target *models.Target, worker *models.Worker) {
	for _, port := range target.Ports {
		wt.Track(execID, target.Host, port.PortID, port.Protocol, worker)
	}
}

// IsTrackedForTarget checks if a worker has processed any port on a target
func (wt *WorkerTracker) IsTrackedForTarget(execID uuid.UUID, target *models.Target, worker *models.Worker) bool {
	for _, port := range target.Ports {
		if wt.IsTracked(execID, target.Host, port.PortID, port.Protocol, worker) {
			return true
		}
	}
	return false
}
