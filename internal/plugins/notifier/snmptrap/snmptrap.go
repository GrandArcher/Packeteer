// Package snmptrap implements the "snmptrap" notifier: each event is sent
// as an SNMPv2c or SNMPv3 trap, or as an inform that the receiver
// acknowledges, to one receiver. The community and SNMPv3 passphrases are
// read from environment variables named in config.
package snmptrap

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GrandArcher/Packeteer/internal/plugins/snmpcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "snmptrap"

// Standard OIDs.
const (
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSnmpTrapOID = "1.3.6.1.6.3.1.1.4.1.0"
)

// Defaults and bounds.
const (
	DefaultPort    = 162
	DefaultTimeout = 5 * time.Second
	MaxTimeout     = time.Minute
	maxValue       = 1024

	// informRetries is how often an unacknowledged inform is sent again.
	// The notifier timeout covers all attempts.
	informRetries = 2
)

func init() { plugin.Notifiers.Register(TypeName, New) }

// Config is the snmptrap notifier's config block.
type Config struct {
	Address       string        `yaml:"address"`
	Port          int           `yaml:"port"`
	Version       string        `yaml:"version"`
	CommunityEnv  string        `yaml:"community_env"`
	UsernameEnv   string        `yaml:"username_env"`
	SecurityLevel string        `yaml:"security_level"`
	AuthProtocol  string        `yaml:"auth_protocol"`
	AuthEnv       string        `yaml:"auth_env"`
	PrivProtocol  string        `yaml:"priv_protocol"`
	PrivEnv       string        `yaml:"priv_env"`
	EngineID      string        `yaml:"engine_id"`
	Inform        bool          `yaml:"inform"`
	EnterpriseOID string        `yaml:"enterprise_oid"`
	Timeout       time.Duration `yaml:"timeout"`

	plugin.EventFilter `yaml:",inline"`
}

// Notifier sends traps.
type Notifier struct {
	plugin.Base
	address string
	port    uint16
	version gosnmp.SnmpVersion
	comm    string
	flags   gosnmp.SnmpV3MsgFlags
	usm     *gosnmp.UsmSecurityParameters
	base    string
	inform  bool
	timeout time.Duration
	gate    *plugin.EventGate
	started time.Time
	now     func() time.Time
}

// New is the plugin factory. It does no network I/O.
func New(c plugin.Config, e plugin.Env) (plugin.Notifier, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	getenv := e.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	gate, err := plugin.NewEventGate(cfg.EventFilter)
	if err != nil {
		return nil, err
	}
	n := &Notifier{gate: gate, now: time.Now}
	n.started = n.now()
	addr := strings.TrimSpace(cfg.Address)
	if addr == "" {
		return nil, fmt.Errorf("address is required")
	}
	if _, err := netip.ParseAddr(addr); err != nil && strings.ContainsAny(addr, " /:") {
		return nil, fmt.Errorf("address %q must be a hostname or IP address", cfg.Address)
	}
	n.address = addr
	port := cfg.Port
	if port == 0 {
		port = DefaultPort
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port %d must be between 1 and 65535", cfg.Port)
	}
	n.port = uint16(port)
	if n.base, err = snmpcfg.EnterpriseOID(cfg.EnterpriseOID); err != nil {
		return nil, err
	}
	if cfg.Timeout < 0 || cfg.Timeout > MaxTimeout {
		return nil, fmt.Errorf("timeout %s must be between 0 and %s", cfg.Timeout, MaxTimeout)
	}
	n.inform = cfg.Inform
	n.timeout = cfg.Timeout
	if n.timeout == 0 {
		n.timeout = DefaultTimeout
	}
	switch cfg.Version {
	case "", "2c", "v2c":
		n.version = gosnmp.Version2c
		if cfg.UsernameEnv != "" || cfg.SecurityLevel != "" || cfg.AuthProtocol != "" || cfg.AuthEnv != "" ||
			cfg.PrivProtocol != "" || cfg.PrivEnv != "" || cfg.EngineID != "" {
			return nil, fmt.Errorf("version 2c uses community_env only")
		}
		if n.comm, err = snmpcfg.Secret(getenv, "community_env", cfg.CommunityEnv, 1); err != nil {
			return nil, err
		}
	case "3", "v3":
		n.version = gosnmp.Version3
		if cfg.CommunityEnv != "" {
			return nil, fmt.Errorf("community_env is only used with version 2c")
		}
		usm, flags, err := snmpcfg.V3{UsernameEnv: cfg.UsernameEnv, SecurityLevel: cfg.SecurityLevel,
			AuthProtocol: cfg.AuthProtocol, AuthEnv: cfg.AuthEnv, PrivProtocol: cfg.PrivProtocol, PrivEnv: cfg.PrivEnv}.USM(getenv)
		if err != nil {
			return nil, err
		}
		n.flags = flags
		if cfg.Inform {
			// The receiver is authoritative for an inform, so its engine ID
			// is discovered, not configured.
			if cfg.EngineID != "" {
				return nil, fmt.Errorf("engine_id is not used with inform: the receiver's engine ID is discovered")
			}
		} else {
			if usm.AuthoritativeEngineID, err = snmpcfg.EngineID(cfg.EngineID); err != nil {
				return nil, fmt.Errorf("%w (required for version 3 traps)", err)
			}
		}
		n.usm = usm
	default:
		return nil, fmt.Errorf("version %q is invalid (want 2c or 3)", cfg.Version)
	}
	return n, nil
}

// EventGate implements plugin.Gated.
func (n *Notifier) EventGate() *plugin.EventGate { return n.gate }

// TrapOID is the notification OID for kind: <enterprise>.0.<trap_id>.
func (n *Notifier) TrapOID(kind string) string {
	id := 0
	if s, ok := plugin.LookupEvent(kind); ok {
		id = s.TrapID
	}
	return n.base + ".0." + strconv.Itoa(id)
}

// Varbinds builds the trap body. Objects live under <enterprise>.1:
// .1 kind, .2 severity, .3 message, .4 time (RFC 3339), .5 fields
// ("k=v; k=v", sorted), .6 dedup key.
func (n *Notifier) Varbinds(e plugin.Event) []gosnmp.SnmpPDU {
	up := n.now().Sub(n.started) / (10 * time.Millisecond)
	if up < 0 {
		up = 0
	}
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + e.Fields[k]
	}
	str := func(i int, v string) gosnmp.SnmpPDU {
		if len(v) > maxValue {
			v = v[:maxValue]
		}
		return gosnmp.SnmpPDU{Name: n.base + ".1." + strconv.Itoa(i) + ".0", Type: gosnmp.OctetString, Value: v}
	}
	return []gosnmp.SnmpPDU{
		{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(up)},
		{Name: oidSnmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: n.TrapOID(e.Kind)},
		str(1, e.Kind),
		str(2, string(e.Severity)),
		str(3, e.Message),
		str(4, e.Time.UTC().Format(time.RFC3339)),
		str(5, strings.Join(parts, "; ")),
		str(6, e.DedupKey()),
	}
}

// Notify implements plugin.Notifier.
func (n *Notifier) Notify(ctx context.Context, e plugin.Event) error {
	if !n.gate.Match(e) {
		return nil
	}
	timeout := n.timeout
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d < timeout {
			timeout = d
		}
	}
	if timeout <= 0 {
		return fmt.Errorf("snmptrap: %w", context.DeadlineExceeded)
	}
	g := &gosnmp.GoSNMP{
		Target:    n.address,
		Port:      n.port,
		Transport: "udp",
		Version:   n.version,
		Community: n.comm,
		Timeout:   timeout,
		Retries:   0,
		Context:   ctx,
		MaxOids:   gosnmp.MaxOids,
	}
	if n.inform {
		g.Retries = informRetries
		g.Timeout = timeout / (informRetries + 1)
	}
	if n.version == gosnmp.Version3 {
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = n.flags
		g.SecurityParameters = n.usm.Copy()
	}
	if err := g.Connect(); err != nil {
		return fmt.Errorf("snmptrap: %w", err)
	}
	defer g.Conn.Close()
	if _, err := g.SendTrap(gosnmp.SnmpTrap{Variables: n.Varbinds(e), IsInform: n.inform}); err != nil {
		return fmt.Errorf("snmptrap: %w", err)
	}
	return nil
}
