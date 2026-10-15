// Package rtr is the built-in RTR origin-validation plugin (#158). It
// connects read-only to an RPKI-to-Router server (RFC 8210) such as the
// operator's Routinator, caches the validated ROA payloads, and answers
// RFC 6811 origin-validation queries. It never announces routes and never
// changes the learned RIB.
package rtr

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "rtr"

// Defaults and bounds.
const (
	DefaultRefresh   = 5 * time.Minute
	DefaultStaleness = time.Hour
	DefaultTimeout   = 30 * time.Second
	MinRefresh       = time.Second
	MaxRefresh       = 24 * time.Hour
	MinTimeout       = time.Second
	MaxTimeout       = 5 * time.Minute
	// maxVRPs bounds the cache a single server can grow, so a broken or
	// hostile server cannot exhaust memory. It is well above the public
	// RPKI table.
	maxVRPs = 2_000_000
	// maxPDU bounds one decoded PDU. Prefix PDUs are small; the bound only
	// stops a bad length field from allocating arbitrarily.
	maxPDU = 1 << 20
)

// RTR PDU types (RFC 8210 section 5).
const (
	pduSerialNotify  = 0
	pduSerialQuery   = 1
	pduResetQuery    = 2
	pduCacheResponse = 3
	pduIPv4Prefix    = 4
	pduIPv6Prefix    = 6
	pduEndOfData     = 7
	pduCacheReset    = 8
	pduRouterKey     = 9
	pduErrorReport   = 10
)

// RTR protocol version spoken (RFC 8210).
const protocolVersion = 1

// RTR error report codes.
const errNoDataAvailable = 2

const maxBackoff = time.Minute

func init() { plugin.RPKIs.Register(TypeName, New) }

// Config is the plugin's config block. address is one server; an ordered
// rpki.sources list of rtr sources gives fallback.
type Config struct {
	// Address is the RTR server, host:port.
	Address string `yaml:"address"`
	// Refresh is how often a healthy session is polled (default 5m).
	Refresh time.Duration `yaml:"refresh"`
	// Staleness is how long a cache is served after the last fetch; older
	// or missing data is unknown (default 1h).
	Staleness time.Duration `yaml:"staleness"`
	// Timeout bounds dial and one read wait (default 30s).
	Timeout time.Duration `yaml:"timeout"`
}

// Client is one RTR connection and its VRP cache.
type Client struct {
	plugin.Base

	name  string
	cfg   Config
	cache *rpki.VRPs

	mu      sync.Mutex
	up      bool
	updated time.Time
	lastErr string

	sessionID uint16
	serial    uint32

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New is the plugin factory. It validates the config and does not connect.
func New(c plugin.Config, env plugin.Env) (plugin.RPKI, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	addr, err := parseAddress(cfg.Address)
	if err != nil {
		return nil, err
	}
	cfg.Address = addr
	if cfg.Refresh == 0 {
		cfg.Refresh = DefaultRefresh
	}
	if cfg.Refresh < MinRefresh || cfg.Refresh > MaxRefresh {
		return nil, fmt.Errorf("refresh %s must be between %s and %s", cfg.Refresh, MinRefresh, MaxRefresh)
	}
	if cfg.Staleness == 0 {
		cfg.Staleness = DefaultStaleness
		if cfg.Staleness < cfg.Refresh {
			cfg.Staleness = cfg.Refresh
		}
	}
	if cfg.Staleness < cfg.Refresh || cfg.Staleness > MaxRefresh {
		return nil, fmt.Errorf("staleness %s must be between refresh (%s) and %s", cfg.Staleness, cfg.Refresh, MaxRefresh)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Timeout < MinTimeout || cfg.Timeout > MaxTimeout {
		return nil, fmt.Errorf("timeout %s must be between %s and %s", cfg.Timeout, MinTimeout, MaxTimeout)
	}
	return &Client{name: env.Name, cfg: cfg, cache: rpki.NewVRPs()}, nil
}

// parseAddress requires an explicit host:port, so a bare host cannot
// silently use the wrong port.
func parseAddress(s string) (string, error) {
	s = strings.TrimSpace(s)
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("address %q must be host:port", s)
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return "", fmt.Errorf("address %q has an invalid port", s)
	}
	return s, nil
}

// Start begins the connection loop. It does not block.
func (c *Client) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.run(ctx)
	}()
	return nil
}

// Stop cancels the loop and waits for it. It returns when ctx expires.
func (c *Client) Stop(ctx context.Context) error {
	if c.cancel != nil {
		c.cancel()
	}
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Validate returns the cached RFC 6811 state. Data older than staleness is
// unknown (fail open).
func (c *Client) Validate(prefix netip.Prefix, origin uint32) plugin.RPKIValidity {
	c.mu.Lock()
	stale := c.updated.IsZero() || time.Since(c.updated) > c.cfg.Staleness
	cache := c.cache
	c.mu.Unlock()
	if stale {
		return plugin.RPKIUnknown
	}
	return cache.Validate(prefix, origin)
}

// Status reports the source's health.
func (c *Client) Status() plugin.RPKIStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return plugin.RPKIStatus{
		Source:  c.name,
		Up:      c.up,
		Stale:   c.updated.IsZero() || time.Since(c.updated) > c.cfg.Staleness,
		VRPs:    c.cache.Len(),
		Updated: c.updated,
		Error:   c.lastErr,
	}
}

// run reconnects until ctx is cancelled.
func (c *Client) run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := c.session(ctx)
		c.setDown(err)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > 2*time.Minute {
			// A long-lived session resets the backoff.
			backoff = time.Second
		}
		if !sleepCtx(ctx, backoff) {
			return
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// session dials the server and runs one connection until it fails.
func (c *Client) session(ctx context.Context) error {
	d := net.Dialer{Timeout: c.cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", c.cfg.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if err := writePDU(conn, resetQuery()); err != nil {
		return err
	}
	// A reset response is the full table: build it aside and swap at End
	// of Data, so a dropped connection leaves the last cache in place.
	// awaiting is true until the response to a query reaches End of Data
	// (or an Error Report). It bounds that wait by timeout, so a silent
	// server is dropped and redialed instead of held forever.
	pending := rpki.NewVRPs()
	awaiting := true
	var buf []byte
	tmp := make([]byte, 64<<10)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wait := c.cfg.Refresh
		if pending != nil || awaiting {
			wait = c.cfg.Timeout
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			var pdus [][]byte
			pdus, buf, err = splitPDUs(buf)
			if err != nil {
				return err
			}
			for _, pdu := range pdus {
				var reply []byte
				var done bool
				pending, reply, done, err = c.handle(pdu, pending)
				if err != nil {
					return err
				}
				if reply != nil {
					if err := writePDU(conn, reply); err != nil {
						return err
					}
					awaiting = true
				}
				if done {
					awaiting = false
				}
			}
		}
		if rerr == nil {
			continue
		}
		var ne net.Error
		if errors.As(rerr, &ne) && ne.Timeout() && ctx.Err() == nil {
			if pending != nil || awaiting {
				// A reset load or a query response stalled: drop the
				// connection so run redials instead of waiting forever.
				return errors.New("rtr: timed out waiting for the server")
			}
			// Idle for one refresh: ask for changes.
			if err := writePDU(conn, c.query()); err != nil {
				return err
			}
			awaiting = true
			continue
		}
		return rerr
	}
}

// query is the next query for the current session: a serial query once a
// full load has completed, else a reset query.
func (c *Client) query() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.updated.IsZero() {
		return resetQuery()
	}
	return serialQuery(c.sessionID, c.serial)
}

// handle applies one PDU and returns the pending table, an optional reply
// to write, and whether the response cycle reached its end. pending is the
// table a full reset is building; nil applies records to the live cache
// (serial updates).
func (c *Client) handle(pdu []byte, pending *rpki.VRPs) (*rpki.VRPs, []byte, bool, error) {
	switch pdu[1] {
	case pduCacheResponse:
		return pending, nil, false, nil
	case pduIPv4Prefix, pduIPv6Prefix:
		prefix, maxLen, asn, announce, err := decodePrefix(pdu)
		if err != nil {
			return pending, nil, false, err
		}
		dst := pending
		if dst == nil {
			dst = c.liveCache()
		}
		if announce {
			if dst.Len() >= maxVRPs {
				return pending, nil, false, fmt.Errorf("rtr: VRP cache exceeds %d payloads", maxVRPs)
			}
			dst.Add(prefix, maxLen, asn)
		} else {
			dst.Remove(prefix, maxLen, asn)
		}
		return pending, nil, false, nil
	case pduEndOfData:
		serial, err := decodeEndOfData(pdu)
		if err != nil {
			return pending, nil, false, err
		}
		if pending != nil {
			c.mu.Lock()
			c.cache = pending
			c.mu.Unlock()
			pending = nil
		}
		c.setUp(serial, binary.BigEndian.Uint16(pdu[2:4]))
		return pending, nil, true, nil
	case pduSerialNotify:
		if len(pdu) < 12 {
			return pending, nil, false, errors.New("rtr: short serial notify")
		}
		return pending, serialQuery(binary.BigEndian.Uint16(pdu[2:4]), binary.BigEndian.Uint32(pdu[8:12])), false, nil
	case pduCacheReset:
		return rpki.NewVRPs(), resetQuery(), false, nil
	case pduRouterKey:
		// RFC 8210 section 5.9: a Router Key does not affect prefix
		// origin validation. Ignore it and keep reading to End of Data.
		return pending, nil, false, nil
	case pduErrorReport:
		if len(pdu) < 8 {
			return pending, nil, false, errors.New("rtr: short error report")
		}
		if code := binary.BigEndian.Uint16(pdu[2:4]); code != errNoDataAvailable {
			return pending, nil, false, fmt.Errorf("rtr: error report code %d", code)
		}
		// The server has no data: an empty cache is valid and fresh.
		c.mu.Lock()
		c.cache = rpki.NewVRPs()
		c.mu.Unlock()
		c.setUp(0, 0)
		return nil, nil, true, nil
	default:
		return pending, nil, false, fmt.Errorf("rtr: unexpected PDU type %d", pdu[1])
	}
}

func (c *Client) liveCache() *rpki.VRPs {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cache
}

func (c *Client) setUp(serial uint32, sessionID uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.up, c.updated, c.lastErr = true, time.Now(), ""
	c.serial, c.sessionID = serial, sessionID
}

func (c *Client) setDown(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.up = false
	if err != nil && !errors.Is(err, context.Canceled) {
		c.lastErr = err.Error()
	}
}

// decodePrefix decodes an IPv4 or IPv6 Prefix PDU (RFC 8210 5.5, 5.6).
func decodePrefix(pdu []byte) (netip.Prefix, uint8, uint32, bool, error) {
	v4 := pdu[1] == pduIPv4Prefix
	want := 20
	if !v4 {
		want = 32
	}
	if len(pdu) < want {
		return netip.Prefix{}, 0, 0, false, errors.New("rtr: short prefix PDU")
	}
	addr, ok := netip.AddrFromSlice(pdu[12 : want-4])
	if !ok {
		return netip.Prefix{}, 0, 0, false, errors.New("rtr: bad prefix address")
	}
	prefixLen := int(pdu[9])
	if prefixLen > addr.BitLen() {
		return netip.Prefix{}, 0, 0, false, fmt.Errorf("rtr: prefix length %d exceeds %d", prefixLen, addr.BitLen())
	}
	return netip.PrefixFrom(addr, prefixLen).Masked(), pdu[10], binary.BigEndian.Uint32(pdu[want-4 : want]), pdu[8]&1 == 1, nil
}

// decodeEndOfData reads the serial number. RFC 8210 also carries the
// refresh, retry, and expire intervals; the client uses its own timers.
func decodeEndOfData(pdu []byte) (uint32, error) {
	if len(pdu) < 12 {
		return 0, errors.New("rtr: short end of data")
	}
	return binary.BigEndian.Uint32(pdu[8:12]), nil
}

func resetQuery() []byte {
	b := make([]byte, 8)
	b[0], b[1] = protocolVersion, pduResetQuery
	binary.BigEndian.PutUint32(b[4:8], uint32(len(b)))
	return b
}

func serialQuery(sessionID uint16, serial uint32) []byte {
	b := make([]byte, 12)
	b[0], b[1] = protocolVersion, pduSerialQuery
	binary.BigEndian.PutUint16(b[2:4], sessionID)
	binary.BigEndian.PutUint32(b[4:8], uint32(len(b)))
	binary.BigEndian.PutUint32(b[8:12], serial)
	return b
}

func writePDU(conn net.Conn, pdu []byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := conn.Write(pdu)
	return err
}

// splitPDUs returns every complete PDU in buf and the trailing partial one.
func splitPDUs(buf []byte) ([][]byte, []byte, error) {
	var out [][]byte
	for {
		if len(buf) < 8 {
			return out, buf, nil
		}
		l := binary.BigEndian.Uint32(buf[4:8])
		if l < 8 || l > maxPDU {
			return nil, nil, fmt.Errorf("rtr: invalid PDU length %d", l)
		}
		if uint32(len(buf)) < l {
			return out, buf, nil
		}
		out = append(out, buf[:l])
		buf = buf[l:]
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
