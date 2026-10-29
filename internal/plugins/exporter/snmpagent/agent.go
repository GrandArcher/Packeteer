// Package snmpagent implements the "snmpagent" exporter: a read-only SNMP
// agent (v2c, v3, or both on one UDP port) that serves the Packeteer MIB,
// deploy/mib/PACKETEER-MIB.txt, so an SNMP NMS can poll Packeteer.
//
// It takes the metrics stream, so what it serves is the latest snapshot of
// GET /metrics (taken every plugin.MetricsInterval), and pktrDataAge says
// how old that is. It never answers a SET, announces nothing, and feeds no
// decision.
package snmpagent

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GrandArcher/Packeteer/internal/plugins/snmpcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "snmpagent"

const (
	// maxVarbinds is the most variable bindings the agent reads from, or
	// puts in, one message.
	maxVarbinds = 64
	// oidUnknownEngineIDs is usmStatsUnknownEngineIDs.0 (RFC 3414).
	oidUnknownEngineIDs = ".1.3.6.1.6.3.15.1.1.4.0"
	// bootsEpoch makes the engine boots counter the seconds since
	// 2020-01-01, so it grows across restarts without a state file
	// (RFC 3414 wants a counter that does). It fits the 31 bits RFC 3411
	// allows until 2088.
	bootsEpoch = 1577836800
	// defaultEngineID is the RFC 3411 format 4 (administrator text) ID
	// 0x80 | enterprise 32473 (the documentation number of RFC 5612) | "packeteer".
	defaultEngineID = "80007ed904" + "7061636b6574656572"
)

func init() { plugin.Exporters.Register(TypeName, New) }

// Config is the snmpagent exporter's config block.
type Config struct {
	// Listen is the UDP address, for example 127.0.0.1:161.
	Listen string `yaml:"listen"`
	// CommunityEnv turns on v2c. UsernameEnv turns on v3. At least one.
	CommunityEnv  string   `yaml:"community_env"`
	UsernameEnv   string   `yaml:"username_env"`
	SecurityLevel string   `yaml:"security_level"`
	AuthProtocol  string   `yaml:"auth_protocol"`
	AuthEnv       string   `yaml:"auth_env"`
	PrivProtocol  string   `yaml:"priv_protocol"`
	PrivEnv       string   `yaml:"priv_env"`
	EngineID      string   `yaml:"engine_id"`
	EnterpriseOID string   `yaml:"enterprise_oid"`
	AllowFrom     []string `yaml:"allow_from"`
}

// Agent serves the MIB.
type Agent struct {
	listen    string
	base      []uint32
	community string
	usm       *gosnmp.UsmSecurityParameters
	flags     gosnmp.SnmpV3MsgFlags
	engine    string
	boots     uint32
	allow     []netip.Prefix
	now       func() time.Time
	started   time.Time

	cur atomic.Pointer[view]

	// prev is the commit counter of the previous snapshot, for the probe
	// rate. Export is the only user.
	prevAt      time.Time
	prevCommits float64

	// ours decodes with the agent's user, open with no keys.
	ours, open     *gosnmp.GoSNMP
	unknownEngines atomic.Uint32

	mu   sync.Mutex
	conn net.PacketConn
	done chan struct{}
}

// New is the plugin factory. It opens no socket.
func New(c plugin.Config, e plugin.Env) (plugin.Exporter, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	getenv := e.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	a := &Agent{now: time.Now}
	a.started = a.now()
	a.boots = uint32(a.started.Unix() - bootsEpoch)
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen %q must be host:port, for example 127.0.0.1:161", cfg.Listen)
	}
	if host != "" {
		if _, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")); err != nil {
			return nil, fmt.Errorf("listen %q: the host must be an IP address or empty", cfg.Listen)
		}
	}
	if n, err := net.LookupPort("udp", port); err != nil || n < 1 {
		return nil, fmt.Errorf("listen %q: port must be a number from 1 to 65535", cfg.Listen)
	}
	a.listen = cfg.Listen
	base, err := snmpcfg.EnterpriseOID(cfg.EnterpriseOID)
	if err != nil {
		return nil, err
	}
	a.base, _ = parseOID(base)

	if cfg.CommunityEnv == "" && cfg.UsernameEnv == "" {
		return nil, fmt.Errorf("community_env (v2c) or username_env (v3) is required: the agent is not open to anyone")
	}
	if cfg.CommunityEnv != "" {
		if a.community, err = snmpcfg.Secret(getenv, "community_env", cfg.CommunityEnv, 1); err != nil {
			return nil, err
		}
	}
	v3 := snmpcfg.V3{UsernameEnv: cfg.UsernameEnv, SecurityLevel: cfg.SecurityLevel, AuthProtocol: cfg.AuthProtocol,
		AuthEnv: cfg.AuthEnv, PrivProtocol: cfg.PrivProtocol, PrivEnv: cfg.PrivEnv}
	if cfg.UsernameEnv != "" {
		if a.usm, a.flags, err = v3.USM(getenv); err != nil {
			return nil, err
		}
		if a.usm.PrivacyProtocol == gosnmp.DES {
			return nil, fmt.Errorf("priv_protocol DES is not supported by the agent; use AES")
		}
		id := cfg.EngineID
		if id == "" {
			id = defaultEngineID
		}
		if a.usm.AuthoritativeEngineID, err = snmpcfg.EngineID(id); err != nil {
			return nil, err
		}
		a.engine = a.usm.AuthoritativeEngineID
	} else if v3 != (snmpcfg.V3{}) || cfg.EngineID != "" {
		return nil, fmt.Errorf("the v3 keys need username_env")
	}
	for _, s := range cfg.AllowFrom {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			ip, ipErr := netip.ParseAddr(s)
			if ipErr != nil {
				return nil, fmt.Errorf("allow_from %q is not an address or a prefix", s)
			}
			p = netip.PrefixFrom(ip, ip.BitLen())
		}
		a.allow = append(a.allow, p.Masked())
	}
	quiet := gosnmp.NewLogger(nil)
	a.ours = &gosnmp.GoSNMP{Version: gosnmp.Version3, Logger: quiet}
	if a.usm != nil {
		a.usm.Logger = quiet
		a.ours.SecurityModel, a.ours.MsgFlags, a.ours.SecurityParameters = gosnmp.UserSecurityModel, a.flags, a.usm.Copy()
		a.open = &gosnmp.GoSNMP{Version: gosnmp.Version3, Logger: quiet, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.NoAuthNoPriv,
			SecurityParameters: &gosnmp.UsmSecurityParameters{AuthenticationProtocol: gosnmp.NoAuth, PrivacyProtocol: gosnmp.NoPriv, Logger: quiet}}
	}
	return a, nil
}

// Streams implements plugin.Exporter. The agent serves measurements, so it
// takes the metrics stream only.
func (a *Agent) Streams() []string { return []string{plugin.StreamMetrics} }

// Export keeps the newest snapshot. Until the first one arrives (up to
// plugin.MetricsInterval after start) every object is absent.
func (a *Agent) Export(_ context.Context, batch []plugin.ExportRecord) error {
	for _, r := range batch {
		if r.Metrics == nil {
			continue
		}
		var rate *float64
		for _, s := range r.Metrics.Samples {
			if s.Name != "packeteer_probe_prefix_commits" {
				continue
			}
			if dt := r.Metrics.Time.Sub(a.prevAt).Seconds(); !a.prevAt.IsZero() && dt > 0 && s.Value >= a.prevCommits {
				v := (s.Value - a.prevCommits) / dt * 60
				rate = &v
			}
			a.prevAt, a.prevCommits = r.Metrics.Time, s.Value
		}
		a.cur.Store(buildView(a.base, *r.Metrics, rate))
	}
	return nil
}

// Start opens the UDP socket.
func (a *Agent) Start(context.Context) error {
	conn, err := net.ListenPacket("udp", a.listen)
	if err != nil {
		return fmt.Errorf("snmpagent: %w", err)
	}
	done := make(chan struct{})
	a.mu.Lock()
	a.conn, a.done = conn, done
	a.mu.Unlock()
	go a.serve(conn, done)
	return nil
}

// Stop closes the socket and waits for the reader.
func (a *Agent) Stop(context.Context) error {
	a.mu.Lock()
	conn, done := a.conn, a.done
	a.conn, a.done = nil, nil
	a.mu.Unlock()
	if conn != nil {
		conn.Close()
		<-done
	}
	return nil
}

// serve answers datagrams one at a time. A source outside allow_from is
// dropped before anything is parsed, because parsing a v3 message derives
// keys and runs the decoder on bytes nobody has authenticated.
func (a *Agent) serve(conn net.PacketConn, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if ua, ok := from.(*net.UDPAddr); ok && a.allowed(ua.IP) {
			if out := a.reply(buf[:n]); out != nil {
				_, _ = conn.WriteTo(out, from)
			}
		}
	}
}

func (a *Agent) allowed(ip net.IP) bool {
	if len(a.allow) == 0 {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, p := range a.allow {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// msgVersion reads the version of an SNMP message, SEQUENCE { INTEGER, ... },
// without decoding the rest.
func msgVersion(b []byte) (gosnmp.SnmpVersion, bool) {
	if len(b) < 5 || b[0] != 0x30 {
		return 0, false
	}
	i := 2
	if b[1]&0x80 != 0 {
		i += int(b[1] & 0x7f)
	}
	if i+3 > len(b) || b[i] != 0x02 || b[i+1] != 0x01 {
		return 0, false
	}
	return gosnmp.SnmpVersion(b[i+2]), true
}

// reply is the response to one datagram, or nil to stay silent. A request
// that fails authentication is dropped without an answer, as RFC 3414 and
// RFC 3584 allow: a probe learns nothing from a wrong community or user.
// Only requests are answered. An inform is never acknowledged.
func (a *Agent) reply(msg []byte) (out []byte) {
	// The decoder runs on unauthenticated input; whatever it trips on must
	// not take the controller down.
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	ver, ok := msgVersion(msg)
	if !ok {
		return nil
	}
	codec := a.ours
	switch ver {
	case gosnmp.Version2c:
		if a.community == "" {
			return nil
		}
	case gosnmp.Version3:
		if a.usm == nil {
			return nil
		}
		// Keys are derived for the agent's engine ID only. Any other
		// message is read with no keys, which is all that discovery needs.
		if !bytes.Contains(msg, []byte(a.engine)) {
			codec = a.open
		}
	default:
		return nil
	}
	p, err := codec.UnmarshalTrap(msg, false)
	if err != nil {
		return nil
	}
	now := a.now()
	if codec == a.open {
		return a.discovery(p, now)
	}
	switch p.PDUType {
	case gosnmp.GetRequest, gosnmp.GetNextRequest, gosnmp.GetBulkRequest, gosnmp.SetRequest:
	default:
		return nil
	}
	if !a.authentic(p) {
		return nil
	}
	switch {
	case len(p.Variables) > maxVarbinds:
		p.Variables, p.Error, p.ErrorIndex = nil, gosnmp.TooBig, 0
	case p.PDUType == gosnmp.SetRequest:
		// No object is writable. The bindings go back as received.
		p.Error, p.ErrorIndex = gosnmp.NotWritable, 1
	default:
		p.Variables = a.answer(p, now)
		p.Error, p.ErrorIndex = gosnmp.NoError, 0
	}
	p.PDUType = gosnmp.GetResponse
	p.MsgFlags &^= gosnmp.Reportable
	if p.Version == gosnmp.Version3 {
		a.stamp(p, now)
		// A fresh salt for every response: the request's would repeat the
		// cipher's IV under the same key (RFC 3826 section 3.1.2.1).
		if err := a.usm.InitPacket(p); err != nil {
			return nil
		}
	}
	out, err = p.MarshalMsg()
	if err != nil {
		return nil
	}
	return out
}

// stamp sets the engine fields of a v3 response.
func (a *Agent) stamp(p *gosnmp.SnmpPacket, now time.Time) {
	sp := p.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	sp.AuthoritativeEngineID = a.engine
	sp.AuthoritativeEngineBoots = a.boots
	sp.AuthoritativeEngineTime = uint32(max(0, now.Sub(a.started)/time.Second))
	p.ContextEngineID = a.engine
}

// discovery answers a v3 engine discovery request, a message with no engine
// ID and no security, with a Report carrying the engine ID, boots, and time
// (RFC 3414 section 4). Anything else read without keys is dropped.
func (a *Agent) discovery(p *gosnmp.SnmpPacket, now time.Time) []byte {
	sp, ok := p.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok || p.Version != gosnmp.Version3 || p.SecurityModel != gosnmp.UserSecurityModel || p.PDUType != gosnmp.GetRequest ||
		p.MsgFlags&gosnmp.AuthPriv != 0 || sp.AuthoritativeEngineID != "" {
		return nil
	}
	a.stamp(p, now)
	p.PDUType = gosnmp.Report
	p.MsgFlags = gosnmp.NoAuthNoPriv
	p.Error, p.ErrorIndex = gosnmp.NoError, 0
	p.Variables = []gosnmp.SnmpPDU{{Name: oidUnknownEngineIDs, Type: gosnmp.Counter32, Value: a.unknownEngines.Add(1)}}
	out, err := p.MarshalMsg()
	if err != nil {
		return nil
	}
	return out
}

// authentic reports whether a decoded request is one the agent answers.
func (a *Agent) authentic(p *gosnmp.SnmpPacket) bool {
	switch p.Version {
	case gosnmp.Version2c:
		return a.community != "" && subtle.ConstantTimeCompare([]byte(p.Community), []byte(a.community)) == 1
	case gosnmp.Version3:
		sp, ok := p.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		if a.usm == nil || !ok || p.SecurityModel != gosnmp.UserSecurityModel {
			return false
		}
		// The security level is the user's: a request that asks for less
		// than configured is refused, or a client could skip authentication.
		return p.MsgFlags&gosnmp.AuthPriv == a.flags && sp.UserName == a.usm.UserName &&
			sp.AuthoritativeEngineID == a.engine && p.ContextName == "" &&
			(p.ContextEngineID == "" || p.ContextEngineID == a.engine)
	}
	return false
}

// answer is the variable bindings of the response.
func (a *Agent) answer(p *gosnmp.SnmpPacket, now time.Time) []gosnmp.SnmpPDU {
	v := a.cur.Load()
	missing := func(name string, t gosnmp.Asn1BER) gosnmp.SnmpPDU { return gosnmp.SnmpPDU{Name: name, Type: t} }
	get := func(name string) gosnmp.SnmpPDU {
		oid, ok := parseOID(name)
		if ok && v != nil {
			if r, found := v.get(oid); found {
				return v.pdu(r, now)
			}
		}
		return missing(name, gosnmp.NoSuchObject)
	}
	next := func(name string) gosnmp.SnmpPDU {
		oid, ok := parseOID(name)
		if ok && v != nil {
			if r, found := v.next(oid); found {
				return v.pdu(r, now)
			}
		}
		return missing(name, gosnmp.EndOfMibView)
	}
	in := p.Variables
	var out []gosnmp.SnmpPDU
	switch p.PDUType {
	case gosnmp.GetRequest:
		for _, b := range in {
			out = append(out, get(b.Name))
		}
	case gosnmp.GetNextRequest:
		for _, b := range in {
			out = append(out, next(b.Name))
		}
	case gosnmp.GetBulkRequest:
		// RFC 3416 section 4.2.3: the first non-repeaters bindings are
		// read once, the rest max-repetitions times, round by round.
		nr := min(int(p.NonRepeaters), len(in))
		for _, b := range in[:nr] {
			out = append(out, next(b.Name))
		}
		cursor := make([]string, 0, len(in)-nr)
		for _, b := range in[nr:] {
			cursor = append(cursor, b.Name)
		}
		for rep := 0; rep < int(p.MaxRepetitions) && len(cursor) > 0 && len(out) < maxVarbinds; rep++ {
			done := true
			for i, name := range cursor {
				r := next(name)
				out = append(out, r)
				cursor[i] = r.Name
				done = done && r.Type == gosnmp.EndOfMibView
			}
			if done {
				break
			}
		}
		out = out[:min(len(out), maxVarbinds)]
	}
	return out
}
