//go:build !linux

package ebpfpath

import (
	"errors"
	"net/netip"
	"time"
)

// ErrTimeout means no frame arrived inside the read timeout.
var ErrTimeout = errors.New("read timeout")

// Capture is not available off Linux.
type Capture struct{}

// OpenCapture always fails off Linux.
func OpenCapture(string, bool, time.Duration) (*Capture, error) { return nil, ErrUnsupported }

// Read is never reached: OpenCapture fails.
func (*Capture) Read([]byte) (int, error) { return 0, ErrUnsupported }

// Drops is never reached: OpenCapture fails.
func (*Capture) Drops() (uint64, error) { return 0, ErrUnsupported }

// Close is never reached: OpenCapture fails.
func (*Capture) Close() error { return nil }

// Flows is not available off Linux.
type Flows struct{}

// OpenFlows always fails off Linux.
func OpenFlows(string, int) (*Flows, error) { return nil, ErrUnsupported }

// Snapshot is never reached: OpenFlows fails.
func (*Flows) Snapshot() (map[FlowKey]Totals, error) { return nil, ErrUnsupported }

// Close is never reached: OpenFlows fails.
func (*Flows) Close() error { return nil }

// TrackOptions configure OpenTracker.
type TrackOptions struct {
	Interface  string
	Promisc    bool
	Local      []netip.Prefix
	SYNTimeout time.Duration
	MaxFlows   int
	Timeout    time.Duration
}

// Tracker is not available off Linux.
type Tracker struct{}

// OpenTracker always fails off Linux.
func OpenTracker(TrackOptions) (*Tracker, error) { return nil, ErrUnsupported }

// Next is never reached: OpenTracker fails.
func (*Tracker) Next() (Summary, error) { return Summary{}, ErrUnsupported }

// Flows is never reached: OpenTracker fails.
func (*Tracker) Flows() ([]TrackState, error) { return nil, ErrUnsupported }

// Forget is never reached: OpenTracker fails.
func (*Tracker) Forget(TrackKey) error { return ErrUnsupported }

// Drops is never reached: OpenTracker fails.
func (*Tracker) Drops() (uint64, uint64, error) { return 0, 0, ErrUnsupported }

// Close is never reached: OpenTracker fails.
func (*Tracker) Close() error { return nil }
