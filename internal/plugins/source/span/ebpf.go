package span

import (
	"errors"
	"time"

	"github.com/GrandArcher/Packeteer/internal/ebpfpath"
)

// ebpfCapture reads frame heads from the eBPF ring buffer (#229) in place
// of an AF_PACKET socket. The frames are Ethernet, so the tracker decodes
// them exactly as it decodes the raw-socket frames.
type ebpfCapture struct{ c *ebpfpath.Capture }

func openEBPF(iface string, promisc bool, timeout time.Duration) (capture, error) {
	c, err := ebpfpath.OpenCapture(iface, promisc, timeout)
	if err != nil {
		return nil, err
	}
	return ebpfCapture{c}, nil
}

func (ebpfCapture) link() int { return linkEthernet }

func (e ebpfCapture) read(buf []byte) (int, error) {
	n, err := e.c.Read(buf)
	if errors.Is(err, ebpfpath.ErrTimeout) {
		return 0, errReadTimeout
	}
	return n, err
}

func (e ebpfCapture) close() error { return e.c.Close() }

// drops is how many frames the kernel could not queue since start.
func (e ebpfCapture) drops() uint64 {
	n, _ := e.c.Drops()
	return n
}
