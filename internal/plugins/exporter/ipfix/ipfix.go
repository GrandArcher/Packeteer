// Package ipfix implements the "ipfix" exporter: tagged flow records are
// re-exported as IPFIX (RFC 7011) over UDP, so any collector (pmacct,
// GoFlow2, ElastiFlow, Kentik) can read them. Each record carries the
// provider traffic to its prefix uses in interfaceName (IE 82) and the
// improvement ID in flowId (IE 148); the ID is 0 on a native prefix.
package ipfix

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "ipfix"

// Defaults.
const (
	DefaultObservationDomain = 1
	DefaultTemplateInterval  = time.Minute
	// maxMessage keeps a message inside a common path MTU.
	maxMessage = 1400
)

// Template IDs. Data set IDs are the template IDs.
const (
	templateV4 = 256
	templateV6 = 257
)

func init() { plugin.Exporters.Register(TypeName, New) }

// Config is the ipfix exporter's config block.
type Config struct {
	// Address is the collector as host:port (UDP).
	Address string `yaml:"address"`
	// ObservationDomain identifies this exporter to the collector.
	ObservationDomain uint32 `yaml:"observation_domain"`
	// TemplateInterval is how often templates are sent again. UDP can lose
	// the first copy.
	TemplateInterval time.Duration `yaml:"template_interval"`
}

type field struct {
	ie     uint16
	length uint16 // 0xffff is variable
}

// Field order is the record order. IEs: flowEndMilliseconds 153,
// sourceIPv4Address 8, destinationIPv4Address 12, sourceIPv6Address 27,
// destinationIPv6Address 28, protocolIdentifier 4, octetDeltaCount 1,
// destinationIPv4PrefixLength 13, destinationIPv6PrefixLength 30,
// flowId 148, interfaceName 82.
var (
	fieldsV4 = []field{{153, 8}, {8, 4}, {12, 4}, {4, 1}, {1, 8}, {13, 1}, {148, 8}, {82, 0xffff}}
	fieldsV6 = []field{{153, 8}, {27, 16}, {28, 16}, {4, 1}, {1, 8}, {30, 1}, {148, 8}, {82, 0xffff}}
)

// Exporter sends IPFIX over UDP.
type Exporter struct {
	addr     string
	domain   uint32
	interval time.Duration
	now      func() time.Time

	mu           sync.Mutex
	conn         net.Conn
	seq          uint32
	templateSent time.Time
}

// New is the plugin factory. It opens no socket.
func New(c plugin.Config, _ plugin.Env) (plugin.Exporter, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" {
		return nil, errors.New("address must be host:port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("address port %q is invalid", port)
	}
	if cfg.ObservationDomain == 0 {
		cfg.ObservationDomain = DefaultObservationDomain
	}
	if cfg.TemplateInterval < 0 {
		return nil, fmt.Errorf("template_interval %s must not be negative", cfg.TemplateInterval)
	}
	if cfg.TemplateInterval == 0 {
		cfg.TemplateInterval = DefaultTemplateInterval
	}
	return &Exporter{addr: cfg.Address, domain: cfg.ObservationDomain, interval: cfg.TemplateInterval, now: time.Now}, nil
}

// Streams implements plugin.Exporter. IPFIX carries flows only.
func (x *Exporter) Streams() []string { return []string{plugin.StreamFlows} }

// Start opens the UDP socket.
func (x *Exporter) Start(ctx context.Context) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", x.addr)
	if err != nil {
		return fmt.Errorf("ipfix dial: %w", err)
	}
	x.mu.Lock()
	x.conn = c
	x.mu.Unlock()
	return nil
}

// Stop closes the socket.
func (x *Exporter) Stop(context.Context) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.conn != nil {
		err := x.conn.Close()
		x.conn = nil
		return err
	}
	return nil
}

// Export packs the batch into messages of at most maxMessage bytes. IPv4
// and IPv6 records go in separate data sets.
func (x *Exporter) Export(_ context.Context, batch []plugin.ExportRecord) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.conn == nil {
		return errors.New("ipfix exporter is not started")
	}
	var v4, v6 [][]byte
	for _, r := range batch {
		if r.Flow == nil {
			continue
		}
		switch {
		case r.Flow.Dst.Is4():
			v4 = append(v4, record(*r.Flow, false))
		case r.Flow.Dst.Is6():
			v6 = append(v6, record(*r.Flow, true))
		}
	}
	now := x.now()
	for len(v4) > 0 || len(v6) > 0 {
		m := newMessage(x.domain, x.seq, now)
		if now.Sub(x.templateSent) >= x.interval {
			m.templates()
		}
		n := 0
		v4, n = m.data(templateV4, v4, n)
		v6, n = m.data(templateV6, v6, n)
		if n == 0 {
			// A record bigger than a message cannot be sent; drop it
			// rather than loop.
			if len(v4) > 0 {
				v4 = v4[1:]
			} else {
				v6 = v6[1:]
			}
			continue
		}
		if m.hasTemplates {
			x.templateSent = now
		}
		if _, err := x.conn.Write(m.bytes()); err != nil {
			return err
		}
		x.seq += uint32(n)
	}
	return nil
}

func record(f plugin.FlowRecord, v6 bool) []byte {
	b := make([]byte, 0, 80)
	b = binary.BigEndian.AppendUint64(b, uint64(f.Time.UnixMilli()))
	// Some records carry no source, or one of the other family: send the
	// unspecified address rather than drop the flow.
	src := netip.IPv4Unspecified()
	if v6 {
		src = netip.IPv6Unspecified()
	}
	if f.Src.IsValid() && f.Src.Is6() == v6 {
		src = f.Src
	}
	b = append(b, src.AsSlice()...)
	b = append(b, f.Dst.AsSlice()...)
	b = append(b, f.Proto)
	b = binary.BigEndian.AppendUint64(b, f.Bytes)
	plen := byte(0)
	if p, err := netip.ParsePrefix(f.Prefix); err == nil && p.Addr().Is6() == v6 {
		plen = byte(p.Bits())
	}
	b = append(b, plen)
	var id uint64
	if f.ImprovementID != "" {
		id, _ = strconv.ParseUint(f.ImprovementID, 16, 64)
	}
	b = binary.BigEndian.AppendUint64(b, id)
	name := f.Provider
	if len(name) > 254 {
		name = name[:254]
	}
	b = append(b, byte(len(name)))
	return append(b, name...)
}

type message struct {
	buf          []byte
	hasTemplates bool
}

func newMessage(domain, seq uint32, at time.Time) *message {
	b := make([]byte, 16, maxMessage)
	binary.BigEndian.PutUint16(b[0:], 10)
	binary.BigEndian.PutUint32(b[4:], uint32(at.Unix()))
	binary.BigEndian.PutUint32(b[8:], seq)
	binary.BigEndian.PutUint32(b[12:], domain)
	return &message{buf: b}
}

func (m *message) bytes() []byte {
	binary.BigEndian.PutUint16(m.buf[2:], uint16(len(m.buf)))
	return m.buf
}

func (m *message) templates() {
	start := len(m.buf)
	m.buf = binary.BigEndian.AppendUint16(m.buf, 2)
	m.buf = binary.BigEndian.AppendUint16(m.buf, 0)
	for _, t := range []struct {
		id     uint16
		fields []field
	}{{templateV4, fieldsV4}, {templateV6, fieldsV6}} {
		m.buf = binary.BigEndian.AppendUint16(m.buf, t.id)
		m.buf = binary.BigEndian.AppendUint16(m.buf, uint16(len(t.fields)))
		for _, f := range t.fields {
			m.buf = binary.BigEndian.AppendUint16(m.buf, f.ie)
			m.buf = binary.BigEndian.AppendUint16(m.buf, f.length)
		}
	}
	binary.BigEndian.PutUint16(m.buf[start+2:], uint16(len(m.buf)-start))
	m.hasTemplates = true
}

// data appends as many whole records as fit in one data set and returns
// the rest and the running record count.
func (m *message) data(id uint16, recs [][]byte, n int) ([][]byte, int) {
	if len(recs) == 0 || len(m.buf)+4+len(recs[0]) > maxMessage {
		return recs, n
	}
	start := len(m.buf)
	m.buf = binary.BigEndian.AppendUint16(m.buf, id)
	m.buf = binary.BigEndian.AppendUint16(m.buf, 0)
	for len(recs) > 0 && len(m.buf)+len(recs[0]) <= maxMessage {
		m.buf = append(m.buf, recs[0]...)
		recs = recs[1:]
		n++
	}
	binary.BigEndian.PutUint16(m.buf[start+2:], uint16(len(m.buf)-start))
	return recs, n
}
