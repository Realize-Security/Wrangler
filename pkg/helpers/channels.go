package helpers

// ReadNTargetsFromChannel reads n targets in from a channel for processing
func ReadNTargetsFromChannel[T any](ch <-chan T, n int) []T {
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
