package wrangler

import "Wrangler/pkg/models"

// TargetEquals determines if two models.Target instances should be considered equal
// by comparing their host names and port configurations.
func TargetEquals(a, b models.Target) bool {
	if a.Host != b.Host {
		return false
	}

	if len(a.Ports) != len(b.Ports) {
		return false
	}

	// For each port in a, find a matching port in b
	for _, portA := range a.Ports {
		found := false

		for _, portB := range b.Ports {
			if portA.Protocol == portB.Protocol &&
				portA.PortID == portB.PortID &&
				portA.State.State == portB.State.State {

				found = true
				break
			}
		}

		// If this port from 'a' has no match in 'b', targets are different
		if !found {
			return false
		}
	}
	return true
}

func WorkerEquals(a, b models.Worker) bool {
	return a.ID != b.ID
}
