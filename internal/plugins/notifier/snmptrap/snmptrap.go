// Package snmptrap implements the "snmptrap" notifier: each event is sent
// as an SNMPv2c or SNMPv3 trap to one receiver. The community and SNMPv3
// passphrases are read from environment variables named in config.
package snmptrap

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "snmptrap"

// DefaultEnterpriseOID is NET-SNMP's netSnmpPlaypen arc, set aside for
// local experiments. Packeteer has no enterprise number; set
// enterprise_oid to your own arc for production receivers.
const DefaultEnterpriseOID = "1.3.6.1.4.1.8072.9999.9999.7717"

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
	minPassphrase  = 8
	maxUser        = 32
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
	timeout time.Duration
	gate    *plugin.EventGate
	started time.Time
	now     func() time.Time
}

var (
	envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	oidRe   = regexp.MustCompile(`^1(\.(0|[1-9][0-9]{0,9}))+$`)
)

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
	n.base = DefaultEnterpriseOID
	if cfg.EnterpriseOID != "" {
		n.base = strings.TrimPrefix(cfg.EnterpriseOID, ".")
		if !oidRe.MatchString(n.base) {
			return nil, fmt.Errorf("enterprise_oid %q is not a numeric OID", cfg.EnterpriseOID)
		}
	}
	if cfg.Timeout < 0 || cfg.Timeout > MaxTimeout {
		return nil, fmt.Errorf("timeout %s must be between 0 and %s", cfg.Timeout, MaxTimeout)
	}
	n.timeout = cfg.Timeout
	if n.timeout == 0 {
		n.timeout = DefaultTimeout
	}
	secret := func(key, name string, minLen int) (string, error) {
		if !envName.MatchString(name) {
			return "", fmt.Errorf("%s is required and must be an environment variable name", key)
		}
		v := getenv(name)
		if len(v) < minLen {
			if v == "" {
				return "", fmt.Errorf("%s: %s is not set", key, name)
			}
			return "", fmt.Errorf("%s: %s must be at least %d characters", key, name, minLen)
		}
		return v, nil
	}
	switch cfg.Version {
	case "", "2c", "v2c":
		n.version = gosnmp.Version2c
		if cfg.UsernameEnv != "" || cfg.SecurityLevel != "" || cfg.AuthProtocol != "" || cfg.AuthEnv != "" ||
			cfg.PrivProtocol != "" || cfg.PrivEnv != "" || cfg.EngineID != "" {
			return nil, fmt.Errorf("version 2c uses community_env only")
		}
		if n.comm, err = secret("community_env", cfg.CommunityEnv, 1); err != nil {
			return nil, err
		}
	case "3", "v3":
		n.version = gosnmp.Version3
		if cfg.CommunityEnv != "" {
			return nil, fmt.Errorf("community_env is only used with version 2c")
		}
		usm := &gosnmp.UsmSecurityParameters{AuthenticationProtocol: gosnmp.NoAuth, PrivacyProtocol: gosnmp.NoPriv}
		if usm.UserName, err = secret("username_env", cfg.UsernameEnv, 1); err != nil {
			return nil, err
		}
		if len(usm.UserName) > maxUser {
			return nil, fmt.Errorf("username_env: longer than %d characters", maxUser)
		}
		id, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(cfg.EngineID), "0x"))
		if err != nil || len(id) < 5 || len(id) > 32 {
			return nil, fmt.Errorf("engine_id is required for version 3: 5 to 32 bytes of hex")
		}
		usm.AuthoritativeEngineID = string(id)
		level := cfg.SecurityLevel
		if level == "" {
			level = "authPriv"
		}
		switch level {
		case "noAuthNoPriv":
			n.flags = gosnmp.NoAuthNoPriv
		case "authNoPriv":
			n.flags = gosnmp.AuthNoPriv
		case "authPriv":
			n.flags = gosnmp.AuthPriv
		default:
			return nil, fmt.Errorf("security_level %q is invalid (want noAuthNoPriv, authNoPriv, authPriv)", cfg.SecurityLevel)
		}
		if n.flags == gosnmp.NoAuthNoPriv && (cfg.AuthProtocol != "" || cfg.AuthEnv != "") {
			return nil, fmt.Errorf("security_level noAuthNoPriv does not use auth")
		}
		if n.flags != gosnmp.AuthPriv && (cfg.PrivProtocol != "" || cfg.PrivEnv != "") {
			return nil, fmt.Errorf("security_level %s does not use privacy", level)
		}
		if n.flags != gosnmp.NoAuthNoPriv {
			if usm.AuthenticationProtocol, err = authProto(cfg.AuthProtocol); err != nil {
				return nil, err
			}
			if usm.AuthenticationPassphrase, err = secret("auth_env", cfg.AuthEnv, minPassphrase); err != nil {
				return nil, err
			}
		}
		if n.flags == gosnmp.AuthPriv {
			if usm.PrivacyProtocol, err = privProto(cfg.PrivProtocol); err != nil {
				return nil, err
			}
			if usm.PrivacyPassphrase, err = secret("priv_env", cfg.PrivEnv, minPassphrase); err != nil {
				return nil, err
			}
		}
		n.usm = usm
	default:
		return nil, fmt.Errorf("version %q is invalid (want 2c or 3)", cfg.Version)
	}
	return n, nil
}

func authProto(s string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(s) {
	case "", "SHA":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	case "MD5":
		return gosnmp.MD5, nil
	}
	return 0, fmt.Errorf("auth_protocol %q is invalid (want SHA, SHA224, SHA256, SHA384, SHA512, MD5)", s)
}

func privProto(s string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToUpper(s) {
	case "", "AES":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	case "DES":
		return gosnmp.DES, nil
	}
	return 0, fmt.Errorf("priv_protocol %q is invalid (want AES, AES192, AES256, AES192C, AES256C, DES)", s)
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
	if n.version == gosnmp.Version3 {
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = n.flags
		g.SecurityParameters = n.usm.Copy()
	}
	if err := g.Connect(); err != nil {
		return fmt.Errorf("snmptrap: %w", err)
	}
	defer g.Conn.Close()
	if _, err := g.SendTrap(gosnmp.SnmpTrap{Variables: n.Varbinds(e)}); err != nil {
		return fmt.Errorf("snmptrap: %w", err)
	}
	return nil
}
