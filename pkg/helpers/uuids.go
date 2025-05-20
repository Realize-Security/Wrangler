package helpers

import (
	"github.com/google/uuid"
	"sync"
)

type UUIDv1 struct {
	mu sync.Mutex
}

// IDGenerator creates and initializes a new UUIDv1
func IDGenerator() *UUIDv1 {
	return &UUIDv1{}
}

func (r *UUIDv1) Generate() uuid.UUID {
	r.mu.Lock()
	defer r.mu.Unlock()
	return uuid.Must(uuid.NewUUID())
}
