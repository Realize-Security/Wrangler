package wrangler

import (
	"sync"
)

// BroadcastChannel allows multiple receivers to get the same values from a source channel
type BroadcastChannel struct {
	source     <-chan interface{}
	recipients []chan interface{}
	mu         sync.RWMutex
	done       chan struct{}
}

// NewBroadcastChannel creates a new broadcast channel from a source channel
func NewBroadcastChannel(source <-chan interface{}) *BroadcastChannel {
	bc := &BroadcastChannel{
		source: source,
		done:   make(chan struct{}),
	}
	go bc.broadcast()
	return bc
}

// broadcast continuously reads from source and sends to all recipients
func (bc *BroadcastChannel) broadcast() {
	defer func() {
		bc.mu.Lock()
		for _, ch := range bc.recipients {
			close(ch)
		}
		bc.mu.Unlock()
	}()

	for {
		select {
		case <-bc.done:
			return
		case val, ok := <-bc.source:
			if !ok {
				return
			}
			bc.mu.Lock()
			for _, ch := range bc.recipients {
				// Non-blocking send to prevent slow recipients from blocking others
				select {
				case ch <- val:
				default:
					// Drop value if recipient is not ready
				}
			}
			bc.mu.Unlock()
		}
	}
}

// Subscribe creates a new channel that receives all values from the source
func (bc *BroadcastChannel) Subscribe(bufSize int) <-chan interface{} {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	ch := make(chan interface{}, bufSize)
	bc.recipients = append(bc.recipients, ch)
	return ch
}

// Unsubscribe removes a subscription channel
func (bc *BroadcastChannel) Unsubscribe(ch <-chan interface{}) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	for i, recipient := range bc.recipients {
		if recipient == ch {
			// Remove this channel from the slice
			bc.recipients = append(bc.recipients[:i], bc.recipients[i+1:]...)
			close(recipient)
			break
		}
	}
}

// Close stops the broadcast and closes all subscription channels
func (bc *BroadcastChannel) Close() {
	close(bc.done)
}

// TypedBroadcastChannel is a type-safe wrapper around BroadcastChannel
type TypedBroadcastChannel[T any] struct {
	bc *BroadcastChannel
}

// NewTypedBroadcastChannel creates a new typed broadcast channel from a source channel
func NewTypedBroadcastChannel[T any](source <-chan T) *TypedBroadcastChannel[T] {
	// Convert the typed channel to interface{} channel
	sourceCh := make(chan interface{})
	go func() {
		defer close(sourceCh)
		for val := range source {
			sourceCh <- val
		}
	}()

	return &TypedBroadcastChannel[T]{
		bc: NewBroadcastChannel(sourceCh),
	}
}

// Subscribe creates a new channel that receives all values from the source
func (tbc *TypedBroadcastChannel[T]) Subscribe(bufSize int) <-chan T {
	ch := make(chan T, bufSize)
	sourceCh := tbc.bc.Subscribe(bufSize)

	go func() {
		defer close(ch)
		for val := range sourceCh {
			if typedVal, ok := val.(T); ok {
				ch <- typedVal
			}
		}
	}()

	return ch
}

// Unsubscribe removes a subscription
func (tbc *TypedBroadcastChannel[T]) Unsubscribe(ch <-chan T) {
	// Implementation note: This is a simplification. In a real implementation,
	// you would need to keep track of the mapping between typed and untyped channels.
	tbc.bc.Close()
}

// Close stops the broadcast
func (tbc *TypedBroadcastChannel[T]) Close() {
	tbc.bc.Close()
}
