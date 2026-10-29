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
	"context"
	"crypto/subtle"
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

	mu sync.Mutex
	tl *gosnmp.TrapListener
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
	tl := gosnmp.NewTrapListener()
	tl.Params = &gosnmp.GoSNMP{Version: gosnmp.Version3, Logger: gosnmp.NewLogger(nil)}
	if a.usm != nil {
		tl.Params.SecurityModel = gosnmp.UserSecurityModel
		tl.Params.MsgFlags = a.flags
		tl.Params.SecurityParameters = a.usm.Copy()
	}
	tl.OnNewTrap = func(p *gosnmp.SnmpPacket, from *net.UDPAddr) { a.handle(tl, p, from) }
	failed := make(chan error, 1)
	go func() { failed <- tl.Listen(a.listen) }()
	select {
	case <-tl.Listening():
	case err := <-failed:
		return fmt.Errorf("snmpagent: %w", err)
	case <-time.After(5 * time.Second):
		return fmt.Errorf("snmpagent: listening on %s took too long", a.listen)
	}
	a.mu.Lock()
	a.tl = tl
	a.mu.Unlock()
	return nil
}

// Stop closes the socket.
func (a *Agent) Stop(context.Context) error {
	a.mu.Lock()
	tl := a.tl
	a.tl = nil
	a.mu.Unlock()
	if tl != nil {
		tl.Close()
	}
	return nil
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

// authentic reports whether the request is one the agent answers. A request
// that fails is dropped without an answer, as RFC 3584 and RFC 3414 allow:
// a probe learns nothing from a wrong community or user.
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

func (a *Agent) handle(tl *gosnmp.TrapListener, p *gosnmp.SnmpPacket, from *net.UDPAddr) {
	switch p.PDUType {
	case gosnmp.GetRequest, gosnmp.GetNextRequest, gosnmp.GetBulkRequest, gosnmp.SetRequest:
	default:
		return
	}
	if !a.allowed(from.IP) || !a.authentic(p) {
		return
	}
	now := a.now()
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
	if sp, ok := p.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok && p.Version == gosnmp.Version3 {
		sp.AuthoritativeEngineBoots = a.boots
		sp.AuthoritativeEngineTime = uint32(max(0, now.Sub(a.started)/time.Second))
		p.ContextEngineID = a.engine
	}
	_ = tl.SendUDP(p, from)
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
