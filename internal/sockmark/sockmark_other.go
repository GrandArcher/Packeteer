//go:build !linux

package sockmark

import "fmt"

// Apply fails: fwmark and DSCP tagging is implemented for Linux, the
// container platform. A provider that needs it must not be probed
// untagged, so the caller fails closed.
func Apply(fd int, v6 bool, m Marking) error {
	if m.IsZero() {
		return nil
	}
	return fmt.Errorf("%w: fwmark and dscp tagging need Linux", ErrTag)
}
