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
	"io"
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

// maxPDU bounds one decoded PDU. Prefix PDUs are small; the bound only
// stops a bad length field from allocating arbitrarily.
const maxPDU = 1 << 20

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

const maxBackoff = time.Minute

// writeTimeout bounds one PDU write; a variable so a test can shorten it.
var writeTimeout = 10 * time.Second

func init() { plugin.RPKIs.Register(TypeName, New) }

// Config is the plugin's config block. address is one server; an ordered
// rpki.sources list of rtr sources gives fallback. Plain TCP unless tls or
// ssh is set.
type Config struct {
	// Address is the RTR server, host:port.
	Address     string `yaml:"address"`
	rpki.Timing `yaml:",inline"`
	// TLS turns on RTR over TLS.
	TLS *TLSConfig `yaml:"tls"`
	// SSH turns on RTR over SSH.
	SSH *SSHConfig `yaml:"ssh"`
}

// Client is one RTR connection and its VRP cache.
type Client struct {
	plugin.Base

	name  string
	cfg   Config
	tr    transport
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
	if err := cfg.Normalize(0); err != nil {
		return nil, err
	}
	tr, err := newTransport(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{name: env.Name, cfg: cfg, tr: tr, cache: rpki.NewVRPs()}, nil
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
	stale := c.cfg.Stale(c.updated, time.Now())
	cache := c.cache
	c.mu.Unlock()
	if stale {
		return plugin.RPKIUnknown
	}
	return cache.Validate(prefix, origin)
}

// Covering lists the payloads covering p. Data older than staleness is
// none.
func (c *Client) Covering(p netip.Prefix) []plugin.RPKIVRP {
	c.mu.Lock()
	stale := c.cfg.Stale(c.updated, time.Now())
	cache := c.cache
	c.mu.Unlock()
	if stale {
		return nil
	}
	return cache.Covering(p)
}

// Status reports the source's health.
func (c *Client) Status() plugin.RPKIStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return plugin.RPKIStatus{
		Source:  c.name,
		Up:      c.up,
		Stale:   c.cfg.Stale(c.updated, time.Now()),
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

// chunk is one read from the connection.
type chunk struct {
	b   []byte
	err error
}

// session dials the server and runs one connection until it fails.
func (c *Client) session(ctx context.Context) error {
	conn, err := c.tr.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	// Reads run in their own goroutine and the loop times them, because an
	// SSH channel has no read deadline. Closing conn ends the reader.
	reads := make(chan chunk)
	done := make(chan struct{})
	defer close(done)
	go func() {
		tmp := make([]byte, 64<<10)
		for {
			n, err := conn.Read(tmp)
			ch := chunk{b: append([]byte(nil), tmp[:n]...), err: err}
			select {
			case reads <- ch:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	// resp is the response in flight, nil while idle. While it is set the
	// read wait is the timeout, so a silent server is dropped and redialed
	// instead of held forever.
	resp, q := resetRequest()
	if err := writePDU(conn, q); err != nil {
		return err
	}
	var buf []byte
	timer := time.NewTimer(c.cfg.Timeout)
	defer timer.Stop()
	for {
		wait := c.cfg.Refresh
		if resp != nil {
			wait = c.cfg.Timeout
		}
		// Go 1.23 timers: Reset discards a pending expiry, so no drain.
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if resp != nil {
				return errors.New("rtr: timed out waiting for the server")
			}
			// Idle for one refresh: ask for changes.
			resp, q = c.request()
			if err := writePDU(conn, q); err != nil {
				return err
			}
		case ch := <-reads:
			if len(ch.b) > 0 {
				buf = append(buf, ch.b...)
				var pdus [][]byte
				pdus, buf, err = splitPDUs(buf)
				if err != nil {
					return err
				}
				for _, pdu := range pdus {
					var reply []byte
					resp, reply, err = c.handle(pdu, resp)
					if err != nil {
						return err
					}
					if reply != nil {
						if err := writePDU(conn, reply); err != nil {
							return err
						}
					}
				}
			}
			if ch.err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return ch.err
			}
		}
	}
}

// response is the RTR response the client is waiting for. Nothing in it
// reaches the live cache before End of Data, so a dropped session or an
// Error Report partway through leaves the last complete cache serving.
type response struct {
	// table is the full table a Reset Query builds; nil for a Serial
	// Query, whose records collect in delta.
	table *rpki.VRPs
	delta []rpki.Change
	adds  int
}

func resetRequest() (*response, []byte) {
	return &response{table: rpki.NewVRPs()}, resetQuery()
}

// request is the next query and the response it opens: a Serial Query
// from the last serial once a full load has completed, else a Reset Query.
func (c *Client) request() (*response, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.updated.IsZero() {
		return resetRequest()
	}
	return &response{}, serialQuery(c.sessionID, c.serial)
}

// handle applies one PDU to the response in flight and returns the
// response still in flight (nil once End of Data is applied) and an
// optional query to write.
func (c *Client) handle(pdu []byte, resp *response) (*response, []byte, error) {
	switch pdu[1] {
	case pduCacheResponse:
		return resp, nil, nil
	case pduIPv4Prefix, pduIPv6Prefix:
		if resp == nil {
			return nil, nil, errors.New("rtr: prefix PDU outside a response")
		}
		prefix, maxLen, asn, announce, err := decodePrefix(pdu)
		if err != nil {
			return resp, nil, err
		}
		ch := rpki.Change{Prefix: prefix, MaxLen: maxLen, ASN: asn, Withdraw: !announce}
		if resp.table != nil {
			if announce && resp.table.Len() >= rpki.MaxVRPs {
				return resp, nil, fmt.Errorf("rtr: VRP cache exceeds %d payloads", rpki.MaxVRPs)
			}
			resp.table.Apply([]rpki.Change{ch})
			return resp, nil, nil
		}
		if len(resp.delta) >= rpki.MaxVRPs {
			return resp, nil, fmt.Errorf("rtr: serial delta exceeds %d payloads", rpki.MaxVRPs)
		}
		resp.delta = append(resp.delta, ch)
		if announce {
			resp.adds++
		}
		return resp, nil, nil
	case pduEndOfData:
		if resp == nil {
			return nil, nil, errors.New("rtr: end of data outside a response")
		}
		serial, err := decodeEndOfData(pdu)
		if err != nil {
			return resp, nil, err
		}
		if resp.table != nil {
			c.mu.Lock()
			c.cache = resp.table
			c.mu.Unlock()
		} else {
			live := c.liveCache()
			if live.Len()+resp.adds > rpki.MaxVRPs {
				return resp, nil, fmt.Errorf("rtr: VRP cache exceeds %d payloads", rpki.MaxVRPs)
			}
			live.Apply(resp.delta)
		}
		c.setUp(serial, binary.BigEndian.Uint16(pdu[2:4]))
		return nil, nil, nil
	case pduSerialNotify:
		if len(pdu) < 12 {
			return resp, nil, errors.New("rtr: short serial notify")
		}
		// RFC 8210 section 8.2: ignore a notify until End of Data. A
		// query now would be a second one on top of the response in
		// flight, reset or serial; the next refresh asks for the change.
		if resp != nil {
			return resp, nil, nil
		}
		c.mu.Lock()
		synced := !c.updated.IsZero()
		session := c.sessionID
		c.mu.Unlock()
		if !synced {
			// No completed fetch yet, so there is no serial to continue from.
			return nil, nil, nil
		}
		if binary.BigEndian.Uint16(pdu[2:4]) != session {
			// This serial belongs to a different session: reset.
			resp, q := resetRequest()
			return resp, q, nil
		}
		// The notify's serial is the cache's new one. A Serial Query for
		// that serial asks for changes after it, so the delta in between
		// is never applied (RFC 8210 section 5.3). Ask from our last serial.
		resp, q := c.request()
		return resp, q, nil
	case pduCacheReset:
		resp, q := resetRequest()
		return resp, q, nil
	case pduRouterKey:
		// RFC 8210 section 5.9: a Router Key does not affect prefix
		// origin validation. Ignore it and keep reading to End of Data.
		return resp, nil, nil
	case pduErrorReport:
		if len(pdu) < 8 {
			return resp, nil, errors.New("rtr: short error report")
		}
		// RFC 8210 section 8.4: code 2 (No Data Available) is a retry, not
		// an empty VRP set. An empty End of Data is the empty set. Leave
		// the last cache in place and drop the session so run redials.
		// Marking an empty table fresh would make a previously invalid
		// origin look notfound while status stayed up.
		code := binary.BigEndian.Uint16(pdu[2:4])
		return resp, nil, fmt.Errorf("rtr: error report code %d", code)
	default:
		return resp, nil, fmt.Errorf("rtr: unexpected PDU type %d", pdu[1])
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

func writePDU(conn io.Writer, pdu []byte) error {
	if d, ok := conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = d.SetWriteDeadline(time.Now().Add(writeTimeout))
	}
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
