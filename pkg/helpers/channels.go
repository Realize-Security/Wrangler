package helpers

// ReadNTargetsFromChannel reads n targets in from a channel for processing
func ReadNTargetsFromChannel(ch <-chan string, n int) []string {
	targets := make([]string, 0, n)
	for i := 0; i < n; i++ {
		target, ok := <-ch
		if !ok {
			break
		}
		targets = append(targets, target)
	}
	return targets
}
