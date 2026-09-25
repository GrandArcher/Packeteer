package snmp

import (
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const (
	defaultInterval   = 5 * time.Minute
	minInterval       = 30 * time.Second
	maxInterval       = time.Hour
	defaultTimeout    = 5 * time.Second
	minTimeout        = 100 * time.Millisecond
	defaultRetries    = 1
	maxRetries        = 5
	defaultMaxSamples = 100000
	maxMaxSamples     = 1000000
	maxIfIndex        = 2147483647
	maxSecretLen      = 255
	maxUserLen        = 32
	minPassphrase     = 8
)

// Config is the snmp telemetry plugin's config block. Community strings
// and SNMPv3 passphrases are read from the environment. The file names
// the variable. It does not hold the secret.
type Config struct {
	Interval   time.Duration `yaml:"interval"`
	Timeout    time.Duration `yaml:"timeout"`
	Retries    *int          `yaml:"retries"`
	MaxSamples int           `yaml:"max_samples"`
	Hosts      []Host        `yaml:"hosts"`
	Providers  []Binding     `yaml:"providers"`
}

// Host is one SNMP agent. Several providers can share it.
type Host struct {
	Name          string `yaml:"name"`
	Address       string `yaml:"address"`
	Port          int    `yaml:"port"`
	Version       string `yaml:"version"`
	CommunityEnv  string `yaml:"community_env"`
	UsernameEnv   string `yaml:"username_env"`
	SecurityLevel string `yaml:"security_level"`
	AuthProtocol  string `yaml:"auth_protocol"`
	AuthEnv       string `yaml:"auth_env"`
	PrivProtocol  string `yaml:"priv_protocol"`
	PrivEnv       string `yaml:"priv_env"`
	ContextName   string `yaml:"context_name"`
}

// Binding attaches one Packeteer provider to an interface on a host.
type Binding struct {
	Name       string  `yaml:"name"`
	Host       string  `yaml:"host"`
	Interface  string  `yaml:"interface"`
	CommitMbps float64 `yaml:"commit_mbps"`
	BillingDay int     `yaml:"billing_day"`
	Percentile string  `yaml:"percentile"`
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type hostSpec struct {
	name      string
	address   string
	port      uint16
	version   string // "2c" or "3"
	community string
	username  string
	level     string // noAuthNoPriv, authNoPriv, authPriv
	authProto string
	authPass  string
	privProto string
	privPass  string
	context   string
}

func (h hostSpec) secrets() []string {
	var out []string
	for _, s := range []string{h.community, h.username, h.authPass, h.privPass} {
		if len(s) >= 4 {
			out = append(out, s)
		}
	}
	return out
}

type bindingSpec struct {
	name       string
	host       string
	iface      string
	commitMbps float64
	billingDay int
	mode       plugin.PercentileMode
}

func decode(c plugin.Config, getenv func(string) string, providers []string) (time.Duration, time.Duration, int, int, []hostSpec, []bindingSpec, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return 0, 0, 0, 0, nil, nil, err
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	if cfg.Interval == 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.Interval < minInterval || cfg.Interval > maxInterval {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("interval %s must be between %s and %s", cfg.Interval, minInterval, maxInterval)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Timeout < minTimeout || cfg.Timeout >= cfg.Interval {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("timeout %s must be at least %s and shorter than interval %s", cfg.Timeout, minTimeout, cfg.Interval)
	}
	retries := defaultRetries
	if cfg.Retries != nil {
		retries = *cfg.Retries
	}
	if retries < 0 || retries > maxRetries {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("retries %d must be between 0 and %d", retries, maxRetries)
	}
	if cfg.MaxSamples == 0 {
		cfg.MaxSamples = defaultMaxSamples
	}
	if cfg.MaxSamples < 1 || cfg.MaxSamples > maxMaxSamples {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("max_samples %d must be between 1 and %d", cfg.MaxSamples, maxMaxSamples)
	}
	if len(cfg.Hosts) == 0 {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("hosts is required")
	}
	if len(cfg.Providers) == 0 {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("providers is required")
	}

	hosts := make([]hostSpec, 0, len(cfg.Hosts))
	byName := map[string]hostSpec{}
	for i, h := range cfg.Hosts {
		spec, err := compileHost(h, getenv)
		if err != nil {
			return 0, 0, 0, 0, nil, nil, fmt.Errorf("hosts[%d]: %w", i, err)
		}
		if _, ok := byName[spec.name]; ok {
			return 0, 0, 0, 0, nil, nil, fmt.Errorf("hosts[%d]: duplicate name %q", i, spec.name)
		}
		byName[spec.name] = spec
		hosts = append(hosts, spec)
	}

	known := map[string]bool{}
	checkProviders := providers != nil
	for _, n := range providers {
		known[n] = true
	}
	bindings := make([]bindingSpec, 0, len(cfg.Providers))
	seenProv := map[string]bool{}
	for i, b := range cfg.Providers {
		spec, err := compileBinding(b)
		if err != nil {
			return 0, 0, 0, 0, nil, nil, fmt.Errorf("providers[%d]: %w", i, err)
		}
		if seenProv[spec.name] {
			return 0, 0, 0, 0, nil, nil, fmt.Errorf("providers[%d]: duplicate provider %q", i, spec.name)
		}
		seenProv[spec.name] = true
		if _, ok := byName[spec.host]; !ok {
			return 0, 0, 0, 0, nil, nil, fmt.Errorf("providers[%d]: host %q is not in hosts", i, spec.host)
		}
		if checkProviders && !known[spec.name] {
			return 0, 0, 0, 0, nil, nil, fmt.Errorf("providers[%d]: %q is not a configured provider", i, spec.name)
		}
		bindings = append(bindings, spec)
	}
	return cfg.Interval, cfg.Timeout, retries, cfg.MaxSamples, hosts, bindings, nil
}

func compileHost(h Host, getenv func(string) string) (hostSpec, error) {
	name := strings.TrimSpace(h.Name)
	if name == "" {
		return hostSpec{}, fmt.Errorf("name is required")
	}
	if err := validAddress(h.Address); err != nil {
		return hostSpec{}, err
	}
	port := h.Port
	if port == 0 {
		port = 161
	}
	if port < 1 || port > 65535 {
		return hostSpec{}, fmt.Errorf("port %d must be between 1 and 65535", h.Port)
	}
	version, err := canonVersion(h.Version)
	if err != nil {
		return hostSpec{}, err
	}
	spec := hostSpec{name: name, address: strings.TrimSpace(h.Address), port: uint16(port), version: version}
	switch version {
	case "2c":
		if h.UsernameEnv != "" || h.SecurityLevel != "" || h.AuthProtocol != "" || h.AuthEnv != "" || h.PrivProtocol != "" || h.PrivEnv != "" || h.ContextName != "" {
			return hostSpec{}, fmt.Errorf("version 2c uses community_env only")
		}
		community, err := envSecret(getenv, h.CommunityEnv, "community_env", 1)
		if err != nil {
			return hostSpec{}, err
		}
		spec.community = community
	case "3":
		if h.CommunityEnv != "" {
			return hostSpec{}, fmt.Errorf("community_env is only used with version 2c")
		}
		user, err := envSecret(getenv, h.UsernameEnv, "username_env", 1)
		if err != nil {
			return hostSpec{}, err
		}
		if len(user) > maxUserLen {
			return hostSpec{}, fmt.Errorf("username_env %q is longer than %d characters", h.UsernameEnv, maxUserLen)
		}
		level, err := canonLevel(h.SecurityLevel)
		if err != nil {
			return hostSpec{}, err
		}
		spec.username = user
		spec.level = level
		spec.context = h.ContextName
		if len(spec.context) > maxSecretLen {
			return hostSpec{}, fmt.Errorf("context_name is longer than %d characters", maxSecretLen)
		}
		needsAuth := level == "authNoPriv" || level == "authPriv"
		needsPriv := level == "authPriv"
		if !needsAuth && (h.AuthProtocol != "" || h.AuthEnv != "" || h.PrivProtocol != "" || h.PrivEnv != "") {
			return hostSpec{}, fmt.Errorf("security_level %s does not use auth or privacy", level)
		}
		if needsAuth {
			proto, err := canonAuth(h.AuthProtocol)
			if err != nil {
				return hostSpec{}, err
			}
			pass, err := envSecret(getenv, h.AuthEnv, "auth_env", minPassphrase)
			if err != nil {
				return hostSpec{}, err
			}
			spec.authProto = proto
			spec.authPass = pass
		}
		if !needsPriv && (h.PrivProtocol != "" || h.PrivEnv != "") {
			return hostSpec{}, fmt.Errorf("security_level %s does not use privacy", level)
		}
		if needsPriv {
			proto, err := canonPriv(h.PrivProtocol)
			if err != nil {
				return hostSpec{}, err
			}
			pass, err := envSecret(getenv, h.PrivEnv, "priv_env", minPassphrase)
			if err != nil {
				return hostSpec{}, err
			}
			spec.privProto = proto
			spec.privPass = pass
		}
	}
	return spec, nil
}

func compileBinding(b Binding) (bindingSpec, error) {
	name := strings.TrimSpace(b.Name)
	if name == "" {
		return bindingSpec{}, fmt.Errorf("name is required")
	}
	host := strings.TrimSpace(b.Host)
	if host == "" {
		return bindingSpec{}, fmt.Errorf("host is required")
	}
	iface := strings.TrimSpace(b.Interface)
	if iface == "" {
		return bindingSpec{}, fmt.Errorf("interface is required")
	}
	if len(iface) > 255 {
		return bindingSpec{}, fmt.Errorf("interface is longer than 255 characters")
	}
	if b.CommitMbps <= 0 || math.IsNaN(b.CommitMbps) || math.IsInf(b.CommitMbps, 0) || b.CommitMbps > 1e8 {
		return bindingSpec{}, fmt.Errorf("commit_mbps must be greater than 0 and at most 100000000")
	}
	if b.BillingDay < 1 || b.BillingDay > 28 {
		return bindingSpec{}, fmt.Errorf("billing_day %d must be between 1 and 28", b.BillingDay)
	}
	mode, err := parseMode(b.Percentile)
	if err != nil {
		return bindingSpec{}, err
	}
	return bindingSpec{name: name, host: host, iface: iface, commitMbps: b.CommitMbps, billingDay: b.BillingDay, mode: mode}, nil
}

func parseMode(s string) (plugin.PercentileMode, error) {
	switch plugin.PercentileMode(strings.ToLower(strings.TrimSpace(s))) {
	case plugin.PercentileSeparate, plugin.PercentileGreater, plugin.PercentileGreaterSeparate:
		return plugin.PercentileMode(strings.ToLower(strings.TrimSpace(s))), nil
	default:
		return "", fmt.Errorf("percentile %q is invalid (want separate, greater, or greater_separate)", s)
	}
}

func envSecret(getenv func(string) string, key, label string, min int) (string, error) {
	if !envName.MatchString(key) {
		return "", fmt.Errorf("%s %q must be an environment variable name", label, key)
	}
	v := getenv(key)
	if v == "" {
		return "", fmt.Errorf("%s %q is empty or unset", label, key)
	}
	if strings.ContainsAny(v, "\r\n\x00") {
		return "", fmt.Errorf("%s %q contains a newline or NUL", label, key)
	}
	if len(v) > maxSecretLen {
		return "", fmt.Errorf("%s %q is longer than %d characters", label, key, maxSecretLen)
	}
	if len(v) < min {
		return "", fmt.Errorf("%s %q must be at least %d characters", label, key, min)
	}
	return v, nil
}

func validAddress(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("address is required")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if len(s) > 253 || strings.ContainsAny(s, " /\\:@") {
		return fmt.Errorf("address %q must be an IP address or a hostname", s)
	}
	return nil
}

func canonVersion(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "2c", "v2c":
		return "2c", nil
	case "3", "v3":
		return "3", nil
	case "":
		return "", fmt.Errorf("version is required (2c or 3)")
	default:
		return "", fmt.Errorf("version %q is invalid (want 2c or 3)", s)
	}
}

func canonLevel(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "noauthnopriv":
		return "noAuthNoPriv", nil
	case "authnopriv":
		return "authNoPriv", nil
	case "authpriv":
		return "authPriv", nil
	case "":
		return "", fmt.Errorf("security_level is required (noAuthNoPriv, authNoPriv, or authPriv)")
	default:
		return "", fmt.Errorf("security_level %q is invalid (want noAuthNoPriv, authNoPriv, or authPriv)", s)
	}
}

func canonAuth(s string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512":
		return strings.ToUpper(strings.TrimSpace(s)), nil
	case "":
		return "", fmt.Errorf("auth_protocol is required")
	default:
		return "", fmt.Errorf("auth_protocol %q is invalid (want MD5, SHA, SHA224, SHA256, SHA384, or SHA512)", s)
	}
}

func canonPriv(s string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DES", "AES", "AES192", "AES256", "AES192C", "AES256C":
		return strings.ToUpper(strings.TrimSpace(s)), nil
	case "":
		return "", fmt.Errorf("priv_protocol is required")
	default:
		return "", fmt.Errorf("priv_protocol %q is invalid (want DES, AES, AES192, AES256, AES192C, or AES256C)", s)
	}
}

// ifIndex reports n when s is a canonical decimal ifIndex (no leading zero).
func ifIndex(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > maxIfIndex || strconv.Itoa(n) != s {
		return 0, false
	}
	return n, true
}
