// Package syslog implements the "syslog" notifier: each event is sent as
// one RFC 5424 message over UDP (RFC 5426), TCP (octet-counting framing,
// RFC 6587), or TLS (RFC 5425) to one collector.
package syslog

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/GrandArcher/Packeteer/internal/plugins/exporter/sinkcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "syslog"

// Defaults and bounds.
const (
	DefaultTimeout = 5 * time.Second
	MaxTimeout     = time.Minute
	defaultApp     = "packeteer"
	// sdID names the structured data elements. 32473 is the enterprise
	// number RFC 5612 reserves for documentation: Packeteer has none, and
	// an SD-ID without one is reserved by RFC 5424 for IANA.
	sdID = "@32473"
	// maxDatagram is the size RFC 5426 says a receiver SHOULD accept; the
	// free text is cut to fit it. Each structured data value is cut at
	// maxSDValue, so the structured data alone can pass it.
	maxDatagram = 2048
	maxStream   = 8192
	maxSDValue  = 512
)

func init() { plugin.Notifiers.Register(TypeName, New) }

// Config is the syslog notifier's config block.
type Config struct {
	Address   string        `yaml:"address"`
	Port      int           `yaml:"port"`
	Transport string        `yaml:"transport"`
	Facility  string        `yaml:"facility"`
	AppName   string        `yaml:"app_name"`
	Hostname  string        `yaml:"hostname"`
	CAFile    string        `yaml:"ca_file"`
	Timeout   time.Duration `yaml:"timeout"`

	plugin.EventFilter `yaml:",inline"`
}

// Notifier sends events to a syslog collector.
type Notifier struct {
	plugin.Base
	addr      string
	transport string
	tls       *tls.Config
	facility  int
	app, host string
	timeout   time.Duration
	gate      *plugin.EventGate

	mu   sync.Mutex
	conn net.Conn
}

// Facility numbers from RFC 5424 table 1 that an application may use.
var facilities = map[string]int{
	"user": 1, "daemon": 3, "auth": 4, "authpriv": 10,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

var (
	// printUSASCII is the PRINTUSASCII of RFC 5424: no space, no control.
	printUSASCII = regexp.MustCompile(`^[\x21-\x7e]+$`)
	sdName       = regexp.MustCompile(`[^\x21-\x7e]|[=\]"]`)
)

// New is the plugin factory. It does no network I/O.
func New(c plugin.Config, e plugin.Env) (plugin.Notifier, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	gate, err := plugin.NewEventGate(cfg.EventFilter)
	if err != nil {
		return nil, err
	}
	n := &Notifier{gate: gate, transport: cfg.Transport, app: cfg.AppName, host: cfg.Hostname}
	addr := strings.TrimSpace(cfg.Address)
	if addr == "" {
		return nil, fmt.Errorf("address is required")
	}
	if _, err := netip.ParseAddr(addr); err != nil && strings.ContainsAny(addr, " /:") {
		return nil, fmt.Errorf("address %q must be a hostname or IP address", cfg.Address)
	}
	switch n.transport {
	case "":
		n.transport = "udp"
	case "udp", "tcp", "tls":
	default:
		return nil, fmt.Errorf("transport %q is invalid (want udp, tcp, tls)", cfg.Transport)
	}
	port := cfg.Port
	if port == 0 {
		port = 514
		if n.transport == "tls" {
			port = 6514
		}
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port %d must be between 1 and 65535", cfg.Port)
	}
	n.addr = net.JoinHostPort(addr, strconv.Itoa(port))
	if n.tls, err = sinkcfg.TLS(n.transport == "tls", cfg.CAFile); err != nil {
		return nil, err
	}
	if n.tls != nil {
		n.tls.ServerName = addr
	}
	fac := cfg.Facility
	if fac == "" {
		fac = "local0"
	}
	var ok bool
	if n.facility, ok = facilities[fac]; !ok {
		return nil, fmt.Errorf("facility %q is invalid (want user, daemon, auth, authpriv, local0 to local7)", cfg.Facility)
	}
	if n.app == "" {
		n.app = defaultApp
	}
	if len(n.app) > 48 || !printUSASCII.MatchString(n.app) {
		return nil, fmt.Errorf("app_name %q must be 1 to 48 printable ASCII characters without spaces", cfg.AppName)
	}
	if n.host == "" {
		if n.host, _ = os.Hostname(); n.host == "" {
			n.host = "-"
		}
	}
	if len(n.host) > 255 || !printUSASCII.MatchString(n.host) {
		return nil, fmt.Errorf("hostname %q must be 1 to 255 printable ASCII characters without spaces", n.host)
	}
	if cfg.Timeout < 0 || cfg.Timeout > MaxTimeout {
		return nil, fmt.Errorf("timeout %s must be between 0 and %s", cfg.Timeout, MaxTimeout)
	}
	n.timeout = cfg.Timeout
	if n.timeout == 0 {
		n.timeout = DefaultTimeout
	}
	return n, nil
}

// EventGate implements plugin.Gated.
func (n *Notifier) EventGate() *plugin.EventGate { return n.gate }

// priority is the RFC 5424 severity of an event severity.
func priority(s plugin.Severity) int {
	switch s {
	case plugin.SeverityCritical:
		return 2
	case plugin.SeverityWarning:
		return 4
	}
	return 6
}

// Format renders e as one RFC 5424 message, without framing. The message
// id is the event kind, cut to the 32 characters the RFC allows. Event
// fields are structured data, so a collector can match on them.
func (n *Notifier) Format(e plugin.Event) string {
	at := e.Time
	if at.IsZero() {
		at = time.Now()
	}
	kind := e.Kind
	if len(kind) > 32 {
		kind = kind[:32]
	}
	if !printUSASCII.MatchString(kind) {
		kind = "-"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<%d>1 %s %s %s - %s ", n.facility*8+priority(e.Severity),
		at.UTC().Format("2006-01-02T15:04:05.000000Z"), n.host, n.app, kind)
	b.WriteString("[packeteer" + sdID)
	for _, p := range [][2]string{{"kind", e.Kind}, {"severity", string(e.Severity)}, {"dedup", e.DedupKey()}} {
		sdParam(&b, p[0], p[1])
	}
	b.WriteByte(']')
	if len(e.Fields) > 0 {
		b.WriteString("[fields" + sdID)
		for _, k := range slices.Sorted(maps.Keys(e.Fields)) {
			sdParam(&b, k, e.Fields[k])
		}
		b.WriteByte(']')
	}
	msg := oneLine(e.Message)
	limit := maxStream
	if n.transport == "udp" {
		limit = maxDatagram
	}
	if room := limit - b.Len() - 4; len(msg) > room {
		msg = cutUTF8(msg, max(room, 0))
	}
	if msg != "" {
		b.WriteByte(' ')
		if !isASCII(msg) {
			b.WriteString("\xef\xbb\xbf")
		}
		b.WriteString(msg)
	}
	return b.String()
}

// sdParam appends ` name="value"`. A name cannot hold a space, `=`, `]`, or
// a quote, and is at most 32 characters; a value escapes `\`, `"`, and `]`.
func sdParam(b *strings.Builder, name, value string) {
	name = sdName.ReplaceAllString(name, "_")
	if len(name) > 32 {
		name = name[:32]
	}
	value = cutUTF8(oneLine(value), maxSDValue)
	b.WriteByte(' ')
	b.WriteString(name)
	b.WriteString(`="`)
	b.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(value))
	b.WriteByte('"')
}

// oneLine turns control characters into spaces so one event is one line in a
// collector's file.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// cutUTF8 shortens s to at most n bytes without splitting a character.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// Notify implements plugin.Notifier.
func (n *Notifier) Notify(ctx context.Context, e plugin.Event) error {
	if !n.gate.Match(e) {
		return nil
	}
	msg := n.Format(e)
	if n.transport != "udp" {
		msg = strconv.Itoa(len(msg)) + " " + msg
	}
	timeout := n.timeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(dl))
	}
	if timeout <= 0 {
		return fmt.Errorf("syslog: %w", context.DeadlineExceeded)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.transport == "udp" {
		c, err := n.dial(ctx, timeout)
		if err != nil {
			return fmt.Errorf("syslog: %w", err)
		}
		defer c.Close()
		return n.write(c, msg, timeout)
	}
	if n.conn != nil && !alive(n.conn) {
		n.conn.Close()
		n.conn = nil
	}
	if n.conn == nil {
		c, err := n.dial(ctx, timeout)
		if err != nil {
			return fmt.Errorf("syslog: %w", err)
		}
		n.conn = c
	}
	if err := n.write(n.conn, msg, timeout); err != nil {
		n.conn.Close()
		n.conn = nil
		return err
	}
	return nil
}

// alive reports whether the collector has left the connection open. A
// collector never sends, so a read that finds the connection closed or
// reset is the only way to see that before a write, which TCP accepts and
// loses after the peer has closed. A collector that does send data is
// treated as closed too: the notifier reconnects before the next event,
// which still delivers.
func alive(c net.Conn) bool {
	// With nothing to read on an open connection, the read times out at once.
	_ = c.SetReadDeadline(time.Now().Add(time.Millisecond))
	defer c.SetReadDeadline(time.Time{})
	var b [1]byte
	_, err := c.Read(b[:])
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (n *Notifier) write(c net.Conn, msg string, timeout time.Duration) error {
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte(msg)); err != nil {
		return fmt.Errorf("syslog: %w", err)
	}
	return nil
}

func (n *Notifier) dial(ctx context.Context, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	if n.transport == "tls" {
		return (&tls.Dialer{NetDialer: d, Config: n.tls}).DialContext(ctx, "tcp", n.addr)
	}
	return d.DialContext(ctx, n.transport, n.addr)
}

// Stop closes the kept connection.
func (n *Notifier) Stop(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn != nil {
		n.conn.Close()
		n.conn = nil
	}
	return nil
}
