package mikrotik

import (
	"context"

	"github.com/GrandArcher/Packeteer/internal/offload"
	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/routeros"
)

// Snapshot is what one poll of a router gives.
type Snapshot struct {
	L3HW routeros.L3HW
	// CPUPathBps is the traffic the CPU path carries, in bits per second,
	// from the external volume source. CPUPathKnown is false without one.
	CPUPathBps   uint64
	CPUPathKnown bool
}

type reader struct {
	opts Options
	src  func() (Snapshot, bool)
}

func newReader(opts Options, src func() (Snapshot, bool)) offload.Reader {
	return reader{opts: opts, src: src}
}

// Read gives the three dimensions of the profile. A dimension the snapshot
// does not carry is unknown, never zero.
func (r reader) Read(_ context.Context, d offload.Dimension) (offload.Reading, error) {
	if r.src == nil {
		return offload.Reading{}, nil
	}
	s, ok := r.src()
	if !ok || !s.L3HW.Applicable {
		return offload.Reading{}, nil
	}
	switch d {
	case offload.FIBv4:
		a := s.L3HW.Advanced
		if a == nil || !a.HasLPM || a.LPMCap <= 0 || a.LPMUsage < 0 {
			return offload.Reading{}, nil
		}
		return lpmReading(uint64(a.LPMUsage), uint64(a.LPMCap), lpmTarget[r.opts.Model]), nil
	case offload.NextHops:
		m := s.L3HW.Monitor
		if m.NexthopCap <= 0 || m.NexthopUsage < 0 {
			return offload.Reading{}, nil
		}
		return offload.Reading{Used: uint64(m.NexthopUsage), Total: uint64(m.NexthopCap), Known: true}, nil
	case offload.CPU:
		lane, ok := laneBps[r.opts.Model]
		if !ok || !s.CPUPathKnown {
			return offload.Reading{}, nil
		}
		return offload.Reading{Used: s.CPUPathBps, Total: lane, Known: true}, nil
	}
	return offload.Reading{}, nil
}

// lpmReading applies the target as the dimension's total. A table above the
// target reads as full, so the planner sheds down to it; a table above the
// chip's own cap is left as read, which the budget refuses as insane.
func lpmReading(used, total, target uint64) offload.Reading {
	if used > total {
		return offload.Reading{Used: used, Total: total, Known: true}
	}
	if target > 0 && target < total {
		total = target
		used = min(used, total)
	}
	return offload.Reading{Used: used, Total: total, Known: true}
}
