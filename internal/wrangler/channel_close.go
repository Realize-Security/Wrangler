package wrangler

import (
	"fmt"
	"log"
	"reflect"
	"sync"
)

// ChannelRegistry keeps track of all channels in the application with their names
type ChannelRegistry struct {
	channels map[string]interface{}
	mutex    sync.RWMutex
}

// NewChannelRegistry creates a new registry for channels
func NewChannelRegistry() *ChannelRegistry {
	return &ChannelRegistry{
		channels: make(map[string]interface{}),
		mutex:    sync.RWMutex{},
	}
}

// Register adds a channel to the registry
func (cr *ChannelRegistry) Register(name string, ch interface{}) {
	cr.mutex.Lock()
	defer cr.mutex.Unlock()

	// Verify it's a channel using reflection
	v := reflect.ValueOf(ch)
	if v.Kind() != reflect.Chan {
		log.Printf("[!] Attempted to register non-channel %s", name)
		return
	}

	cr.channels[name] = ch
	log.Printf("[*] Registered channel: %s", name)
}

// Unregister removes a channel from the registry
func (cr *ChannelRegistry) Unregister(name string) {
	cr.mutex.Lock()
	defer cr.mutex.Unlock()
	delete(cr.channels, name)
	log.Printf("[*] Unregistered channel: %s", name)
}

// CloseAndDrainChannels closes and drains all registered channels if they're not already closed
func (cr *ChannelRegistry) CloseAndDrainChannels() {
	cr.mutex.RLock()
	defer cr.mutex.RUnlock()

	for name, ch := range cr.channels {
		v := reflect.ValueOf(ch)

		// Check if channel is already closed
		if v.Kind() != reflect.Chan {
			log.Printf("[!] Skipping non-channel %s", name)
			continue
		}

		// Try to close the channel if we can
		isClosed := false

		// We can't directly check if a channel is closed in Go
		// So we'll use a non-blocking receive with a default case
		if v.Type().ChanDir() != reflect.RecvDir { // Skip receive-only channels
			// Use recover in case we try to close an already closed channel
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[!] Channel %s is already closed", name)
						isClosed = true
					}
				}()

				// Use reflection to close the channel
				reflect.ValueOf(ch).Close()
				log.Printf("[*] Closed channel: %s", name)
			}()
		}

		// Drain the channel to avoid goroutine leaks
		if !isClosed {
			count := 0
			for {
				// Try to receive from the channel without blocking
				chosen, _, ok := reflect.Select([]reflect.SelectCase{
					{
						Dir:  reflect.SelectRecv,
						Chan: v,
					},
					{
						Dir: reflect.SelectDefault,
					},
				})

				// If we got the default case or the channel is closed, we're done
				if chosen == 1 || !ok {
					break
				}
				count++
			}

			if count > 0 {
				log.Printf("[!] Channel %s was not empty, drained %d messages", name, count)
			}
		}
	}
}

// RegisterWranglerChannels registers all the channels from a wranglerRepository
func (cr *ChannelRegistry) RegisterWranglerChannels(wr *wranglerRepository) {
	// Register the main channels
	cr.Register("serviceEnum", wr.serviceEnum)
	cr.Register("fullScan", wr.fullScan)
	cr.Register("serviceEnumSource", wr.serviceEnumSource)
	cr.Register("fullScanSource", wr.fullScanSource)

	// Register global channels
	cr.Register("sigCh", sigCh)
	cr.Register("errCh", errCh)

	// Register worker channels
	for i, worker := range wr.staticWorkers {
		cr.Register(fmt.Sprintf("staticWorker[%d].UserCommand", i), worker.UserCommand)
		cr.Register(fmt.Sprintf("staticWorker[%d].WorkerResponse", i), worker.WorkerResponse)
		cr.Register(fmt.Sprintf("staticWorker[%d].ErrorChan", i), worker.ErrorChan)
		cr.Register(fmt.Sprintf("staticWorker[%d].XMLPathsChan", i), worker.XMLPathsChan)
	}

	for i, worker := range wr.templateWorkers {
		cr.Register(fmt.Sprintf("templateWorker[%d].UserCommand", i), worker.UserCommand)
		cr.Register(fmt.Sprintf("templateWorker[%d].WorkerResponse", i), worker.WorkerResponse)
		cr.Register(fmt.Sprintf("templateWorker[%d].ErrorChan", i), worker.ErrorChan)
		cr.Register(fmt.Sprintf("templateWorker[%d].XMLPathsChan", i), worker.XMLPathsChan)
	}

	// Register channels from broadcast objects if they exist
	//if wr.serviceEnumBC != nil {
	//	cr.Register("serviceEnumBC.source", wr.serviceEnumBC.source)
	//	cr.Register("serviceEnumBC.done", wr.serviceEnumBC.done)
	//}
	//
	//if wr.fullScanBC != nil {
	//	cr.Register("fullScanBC.source", wr.fullScanBC.source)
	//	cr.Register("fullScanBC.done", wr.fullScanBC.done)
	//}
}

// Enhance the wranglerRepository to use the channel registry
func (wr *wranglerRepository) InitChannelRegistry() *ChannelRegistry {
	registry := NewChannelRegistry()
	registry.RegisterWranglerChannels(wr)
	return registry
}

// Cleanup adds a cleanup method to the wranglerRepository
func (wr *wranglerRepository) Cleanup() {
	registry := wr.InitChannelRegistry()
	registry.CloseAndDrainChannels()
	log.Println("[*] All channels have been closed and drained")
}
