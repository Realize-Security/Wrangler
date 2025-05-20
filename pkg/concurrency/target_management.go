package concurrency

import (
	"sync"
)

// Registry is a thread-safe collection of items of type T
type Registry[T any] struct {
	mu       sync.RWMutex
	items    []T
	equalsFn func(a, b T) bool
}

// NewRegistry creates a new thread-safe registry with a custom equals function
func NewRegistry[T any](equalsFn func(a, b T) bool) *Registry[T] {
	return &Registry[T]{
		items:    make([]T, 0),
		equalsFn: equalsFn,
	}
}

// Add adds an item to the registry if it doesn't already exist
func (r *Registry[T]) Add(item T) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if item already exists to avoid duplicates
	for _, existing := range r.items {
		if r.equalsFn(existing, item) {
			return
		}
	}
	r.items = append(r.items, item)
}

// AddAll adds multiple items to the registry, skipping any that already exist
func (r *Registry[T]) AddAll(items []T) {
	if len(items) == 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, item := range items {
		exists := false
		for _, existing := range r.items {
			if r.equalsFn(existing, item) {
				exists = true
				break
			}
		}

		if !exists {
			r.items = append(r.items, item)
		}
	}
}

// ReadAndRemoveNFromRegistry reads up to n values from the registry and removes them.
// The removed items are returned as a new slice of pointers.
// If the registry has fewer than n elements, all available elements are returned and removed.
func (r *Registry[T]) ReadAndRemoveNFromRegistry(n int) []*T {
	if n <= 0 {
		return []*T{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Determine how many items to read
	count := n
	if len(r.items) < count {
		count = len(r.items)
	}

	// If no items to read, return empty slice
	if count == 0 {
		return []*T{}
	}

	// UUIDv1 the items to return as pointers
	result := make([]*T, count)
	for i := 0; i < count; i++ {
		// Create a local copy of the item at index i
		item := r.items[i]
		// Store a pointer to this copy in the result slice
		result[i] = &item
	}

	// Remove the read items from the registry
	r.items = r.items[count:]

	return result
}

// Remove removes an item from the registry
func (r *Registry[T]) Remove(item T) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, existing := range r.items {
		if r.equalsFn(existing, item) {
			// Remove item by appending elements before and after it
			r.items = append(r.items[:i], r.items[i+1:]...)
			return true
		}
	}
	return false
}

// Contains checks if an item exists in the registry
func (r *Registry[T]) Contains(item T) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, existing := range r.items {
		if r.equalsFn(existing, item) {
			return true
		}
	}
	return false
}

// GetAll returns a copy of all items
func (r *Registry[T]) GetAll() []T {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Create a copy to avoid exposing the internal slice
	result := make([]T, len(r.items))
	copy(result, r.items)
	return result
}

// Len returns the number of items in the registry
func (r *Registry[T]) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.items)
}

// Clear removes all items from the registry
func (r *Registry[T]) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = make([]T, 0)
}
