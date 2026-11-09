package span

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// maxPcapRecord caps one captured record. A larger length is a corrupt file.
const maxPcapRecord = 256 << 10

// pcapReader reads classic libpcap files (microsecond or nanosecond
// timestamps, either byte order). pcapng is not supported.
type pcapReader struct {
	r     *bufio.Reader
	order binary.ByteOrder
	nano  bool
	link  int
	buf   []byte
}

func newPcapReader(r io.Reader) (*pcapReader, error) {
	br := bufio.NewReader(r)
	var hdr [24]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, fmt.Errorf("pcap header: %w", err)
	}
	p := &pcapReader{r: br}
	switch {
	case binary.LittleEndian.Uint32(hdr[:4]) == 0xa1b2c3d4:
		p.order = binary.LittleEndian
	case binary.BigEndian.Uint32(hdr[:4]) == 0xa1b2c3d4:
		p.order = binary.BigEndian
	case binary.LittleEndian.Uint32(hdr[:4]) == 0xa1b23c4d:
		p.order, p.nano = binary.LittleEndian, true
	case binary.BigEndian.Uint32(hdr[:4]) == 0xa1b23c4d:
		p.order, p.nano = binary.BigEndian, true
	default:
		return nil, errors.New("not a pcap file (pcapng is not supported; convert with editcap -F pcap)")
	}
	p.link = int(p.order.Uint32(hdr[20:24]) & 0x0fffffff)
	switch p.link {
	case linkEthernet, linkRaw, linkLinuxSLL, linkIPv4, linkIPv6:
	default:
		return nil, fmt.Errorf("pcap link type %d is not supported (Ethernet, raw IP, or Linux cooked)", p.link)
	}
	return p, nil
}

// next returns the next record. The slice is reused by the following call.
// It returns io.EOF at a clean end of file.
func (p *pcapReader) next() (time.Time, []byte, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(p.r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return time.Time{}, nil, errors.New("pcap: truncated record header")
		}
		return time.Time{}, nil, err
	}
	sec := int64(p.order.Uint32(hdr[0:4]))
	frac := int64(p.order.Uint32(hdr[4:8]))
	n := p.order.Uint32(hdr[8:12])
	if n > maxPcapRecord {
		return time.Time{}, nil, fmt.Errorf("pcap: record length %d is too large", n)
	}
	if cap(p.buf) < int(n) {
		p.buf = make([]byte, n)
	}
	b := p.buf[:n]
	if _, err := io.ReadFull(p.r, b); err != nil {
		return time.Time{}, nil, errors.New("pcap: truncated record")
	}
	if !p.nano {
		frac *= 1000
	}
	return time.Unix(sec, frac), b, nil
}
