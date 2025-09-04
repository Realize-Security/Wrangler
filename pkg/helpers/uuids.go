package helpers

import (
	"sync"

	"github.com/google/uuid"
)

type UUID struct {
	mu sync.Mutex
}

// Generator creates and initializes a new UUID
func Generator() *UUID {
	return &UUID{}
}

// UUIDv1 generates a UUIDv1
func (r *UUID) UUIDv1() uuid.UUID {
	r.mu.Lock()
	defer r.mu.Unlock()
	return uuid.Must(uuid.NewUUID())
}
