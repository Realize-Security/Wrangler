package helpers

import "Wrangler/pkg/models"

// ReadNTargetsFromChannel reads n targets in from a channel for processing
func ReadNTargetsFromChannel[T any](ch <-chan T, n int) []T {
	// TODO: Test if this can be used instead of continuous
	targets := make([]T, 0, n)
	for i := 0; i < n; i++ {
		select {
		case target, ok := <-ch:
			if !ok {
				return targets
			}
			targets = append(targets, target)
		}
	}
	return targets
}

// ReadTargetsFromChannel reads from ch until it closes, sending batches of size or less
func ReadTargetsFromChannel(ch <-chan models.Target, size int) <-chan []models.Target {
	out := make(chan []models.Target)
	go func() {
		defer close(out)
		batch := make([]models.Target, 0, size)
		for t := range ch {
			batch = append(batch, t)
			if len(batch) == size {
				out <- batch
				batch = make([]models.Target, 0, size)
			}
		}
		if len(batch) > 0 {
			out <- batch
		}
	}()
	return out
}
