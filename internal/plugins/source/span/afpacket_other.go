//go:build !linux

package span

import (
	"errors"
	"time"
)

// openCapture is the non-Linux stub. The container image is Linux; other
// systems still compile, and pcap_file replay works everywhere.
func openCapture(string, bool, time.Duration) (capture, error) {
	return nil, errors.New("span: interface capture is only supported on linux (AF_PACKET)")
}
