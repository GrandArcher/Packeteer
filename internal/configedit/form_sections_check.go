package configedit

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func validateListLen(name string, n int) error {
	if n > MaxFormListValues {
		return fmt.Errorf("%w: %s: at most %d values in the form", ErrForm, name, MaxFormListValues)
	}
	return nil
}

func validDuration(name, v string, min, max time.Duration) error {
	if v == "" {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < min || d > max {
		return fmt.Errorf("%w: %s %q must be a duration from %s to %s (for example 5m)", ErrForm, name, v, min, max)
	}
	return nil
}

func validInt(name, v string, min, max int) error {
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return fmt.Errorf("%w: %s %q must be a whole number from %d to %d", ErrForm, name, v, min, max)
	}
	return nil
}

func validASNs(name string, list []string) error {
	if err := validateListLen(name, len(list)); err != nil {
		return err
	}
	seen := map[uint64]bool{}
	for _, s := range list {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 {
			return fmt.Errorf("%w: %s: %q must be a non-zero AS number", ErrForm, name, s)
		}
		if seen[n] {
			return fmt.Errorf("%w: %s: duplicate AS %d", ErrForm, name, n)
		}
		seen[n] = true
	}
	return nil
}

func validPrefixList(name string, list []string) error {
	if err := validateListLen(name, len(list)); err != nil {
		return err
	}
	seen := map[netip.Prefix]bool{}
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil || p != p.Masked() {
			return fmt.Errorf("%w: %s: %q must be a prefix without host bits", ErrForm, name, s)
		}
		if seen[p] {
			return fmt.Errorf("%w: %s: duplicate prefix %s", ErrForm, name, p)
		}
		seen[p] = true
	}
	return nil
}

func (f Form) validateSections() error {
	if err := f.validateFlows(); err != nil {
		return err
	}
	if err := f.validatePolicies(); err != nil {
		return err
	}
	if err := f.validateVIPs(); err != nil {
		return err
	}
	if err := f.validateOutages(); err != nil {
		return err
	}
	return f.validateProtection()
}

// validateInstances checks one section's list: its size, that each Key
// appears once, and that the instance names (Name, or the type when none
// is set) are unique, which the loader requires.
func validateInstances(what, typ string, keys, names []string) error {
	if len(keys) > MaxFormInstances {
		return fmt.Errorf("%w: at most %d %s entries in the form", ErrForm, MaxFormInstances, what)
	}
	seenKey := map[string]bool{}
	seenName := map[string]bool{}
	for i, k := range keys {
		at := fmt.Sprintf("%s[%d]", what, i)
		if k != "" {
			if seenKey[k] {
				return fmt.Errorf("%w: %s: entry listed twice", ErrForm, at)
			}
			seenKey[k] = true
		}
		n := names[i]
		if strings.ContainsAny(n, "\r\n") {
			return fmt.Errorf("%w: %s: name must be one line", ErrForm, at)
		}
		if n == "" {
			n = typ
		}
		if seenName[n] {
			return fmt.Errorf("%w: %s: two entries are named %q; give each a unique name", ErrForm, at, n)
		}
		seenName[n] = true
	}
	return nil
}

func (f Form) validateFlows() error {
	keys, names := make([]string, len(f.Flows)), make([]string, len(f.Flows))
	for i, fl := range f.Flows {
		keys[i], names[i] = fl.Key, fl.Name
	}
	if err := validateInstances("flow", "flow", keys, names); err != nil {
		return err
	}
	bound := map[string]bool{}
	for i, fl := range f.Flows {
		if err := fl.validate(fmt.Sprintf("flow[%d]", i), bound); err != nil {
			return err
		}
	}
	return nil
}

// validate checks one flow source. bound holds the listen addresses of the
// earlier sources: two collectors cannot share a UDP port.
func (fl FormFlow) validate(at string, bound map[string]bool) error {
	if len(fl.Listen) == 0 {
		return fmt.Errorf("%w: %s: at least one listen address (host:port) is required; remove the collector instead", ErrForm, at)
	}
	if err := validateListLen(at+".listen", len(fl.Listen)); err != nil {
		return err
	}
	for _, l := range fl.Listen {
		host, port, err := net.SplitHostPort(l)
		if err != nil {
			return fmt.Errorf("%w: %s.listen %q is not host:port", ErrForm, at, l)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("%w: %s.listen %q: port must be 0 to 65535", ErrForm, at, l)
		}
		if host != "" {
			a, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("%w: %s.listen %q: host must be an IP address or empty", ErrForm, at, l)
			}
			host = a.String()
		}
		key := net.JoinHostPort(host, port)
		if n != 0 && bound[key] {
			return fmt.Errorf("%w: %s.listen: %s is already used by another collector or twice in this one", ErrForm, at, l)
		}
		bound[key] = true
	}
	if err := validDuration(at+".window", fl.Window, time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validInt(at+".top_n", fl.TopN, 1, 10000); err != nil {
		return err
	}
	if err := validInt(at+".max_targets", fl.MaxTargets, 0, 10000); err != nil {
		return err
	}
	if err := validDuration(at+".tail_interval", fl.TailInterval, time.Second, 24*time.Hour); err != nil {
		return err
	}
	if fl.MinBytes != "" {
		if _, err := strconv.ParseUint(fl.MinBytes, 10, 64); err != nil {
			return fmt.Errorf("%w: %s.min_bytes %q must be a whole number of bytes, zero or more", ErrForm, at, fl.MinBytes)
		}
	}
	if err := numberField(at+".min_pct", fl.MinPct, 0, 100); err != nil {
		return err
	}
	if err := validInt(at+".aggregate_v4", fl.AggregateV4, 1, 32); err != nil {
		return err
	}
	if err := validInt(at+".aggregate_v6", fl.AggregateV6, 1, 128); err != nil {
		return err
	}
	return validPrefixList(at+".exclude", fl.Exclude)
}

var ruleActions = map[string]bool{"ignore": true, "allow": true, "deny": true, "static": true, "vip": true}

func (f Form) validatePolicies() error {
	keys, names := make([]string, len(f.Policies)), make([]string, len(f.Policies))
	total := 0
	for i, p := range f.Policies {
		keys[i], names[i] = p.Key, p.Name
		total += len(p.Rules)
	}
	if err := validateInstances("policies", "rules", keys, names); err != nil {
		return err
	}
	if total > MaxFormRules {
		return fmt.Errorf("%w: at most %d rules in the form", ErrForm, MaxFormRules)
	}
	provs := map[string]bool{}
	for _, pr := range f.Providers {
		provs[pr.Name] = true
	}
	for i, p := range f.Policies {
		if err := p.validate(fmt.Sprintf("policies[%d]", i), provs); err != nil {
			return err
		}
	}
	return nil
}

func (p FormPolicies) validate(pat string, provs map[string]bool) error {
	if len(p.Rules) == 0 {
		return fmt.Errorf("%w: %s: a rules policy needs at least one rule; remove the policy instead", ErrForm, pat)
	}
	if strings.ContainsAny(p.GeoIPDB, "\r\n") || (p.GeoIPDB != "" && !filepath.IsAbs(p.GeoIPDB)) {
		return fmt.Errorf("%w: %s.geoip_db %q must be an absolute path (mount the file into the container)", ErrForm, pat, p.GeoIPDB)
	}
	names := map[string]bool{}
	keys := map[string]bool{}
	for i, r := range p.Rules {
		at := fmt.Sprintf("%s.rules[%d]", pat, i)
		if r.Name != "" {
			if strings.ContainsAny(r.Name, "\r\n") {
				return fmt.Errorf("%w: %s: name must be one line", ErrForm, at)
			}
			if names[r.Name] {
				return fmt.Errorf("%w: %s: duplicate name %s", ErrForm, at, r.Name)
			}
			names[r.Name] = true
			at = fmt.Sprintf("%s (%s)", at, r.Name)
		}
		if r.Key != "" {
			if keys[r.Key] {
				return fmt.Errorf("%w: %s: row listed twice", ErrForm, at)
			}
			keys[r.Key] = true
		}
		if !ruleActions[r.Action] {
			return fmt.Errorf("%w: %s: action %q is invalid (want ignore, allow, deny, static, or vip)", ErrForm, at, r.Action)
		}
		for _, name := range r.Providers {
			if !provs[name] {
				return fmt.Errorf("%w: %s: provider %q is not a provider in this form", ErrForm, at, name)
			}
		}
		switch r.Action {
		case "allow", "deny":
			if len(r.Providers) < 1 {
				return fmt.Errorf("%w: %s: %s needs at least one provider", ErrForm, at, r.Action)
			}
		case "static":
			if len(r.Providers) != 1 {
				return fmt.Errorf("%w: %s: static pins exactly one provider", ErrForm, at)
			}
			if r.MaxLossPct == "" {
				return fmt.Errorf("%w: %s: static needs max_loss_pct (the highest loss the pinned path may show)", ErrForm, at)
			}
		default:
			if len(r.Providers) != 0 {
				return fmt.Errorf("%w: %s: %s takes no providers", ErrForm, at, r.Action)
			}
		}
		if r.Action != "static" && (r.MaxLossPct != "" || r.MaxRTT != "") {
			return fmt.Errorf("%w: %s: max_loss_pct and max_rtt are only for static", ErrForm, at)
		}
		if err := numberField(at+" max_loss_pct", r.MaxLossPct, 0, 100); err != nil {
			return err
		}
		if err := validDuration(at+" max_rtt", r.MaxRTT, 0, 24*time.Hour); err != nil {
			return err
		}
		if err := validPrefixList(at+" prefixes", r.Prefixes); err != nil {
			return err
		}
		if err := validASNs(at+" asns", r.ASNs); err != nil {
			return err
		}
		if err := validateListLen(at+" countries", len(r.Countries)); err != nil {
			return err
		}
		for _, c := range r.Countries {
			if len(c) != 2 || strings.Trim(c, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") != "" {
				return fmt.Errorf("%w: %s: country %q must be a two-letter ISO 3166-1 code", ErrForm, at, c)
			}
		}
		if len(r.Countries) > 0 && p.GeoIPDB == "" {
			return fmt.Errorf("%w: %s: countries need geoip_db on this policy (the path of a mounted MaxMind-format database)", ErrForm, at)
		}
		switch r.Traffic {
		case "", "transit", "local":
		default:
			return fmt.Errorf("%w: %s: traffic %q is invalid (want transit or local)", ErrForm, at, r.Traffic)
		}
		if len(r.Prefixes) == 0 && len(r.ASNs) == 0 && len(r.Countries) == 0 && r.Traffic == "" {
			return fmt.Errorf("%w: %s: a rule needs at least one of prefixes, asns, countries, or traffic", ErrForm, at)
		}
	}
	return nil
}

func (f Form) validateVIPs() error {
	keys, names := make([]string, len(f.VIPs)), make([]string, len(f.VIPs))
	for i, v := range f.VIPs {
		keys[i], names[i] = v.Key, v.Name
	}
	if err := validateInstances("vip", "vip", keys, names); err != nil {
		return err
	}
	for i, v := range f.VIPs {
		if err := v.validate(fmt.Sprintf("vip[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

func (v FormVIP) validate(at string) error {
	if v.Interval == "" {
		return fmt.Errorf("%w: %s.interval is required (for example 10s)", ErrForm, at)
	}
	if err := validDuration(at+".interval", v.Interval, time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validInt(at+".max_targets", v.MaxTargets, 1, 10000); err != nil {
		return err
	}
	if len(v.Prefixes) == 0 && len(v.ASNs) == 0 {
		return fmt.Errorf("%w: %s needs at least one prefix or ASN", ErrForm, at)
	}
	if err := validateListLen(at+".prefixes", len(v.Prefixes)); err != nil {
		return err
	}
	seen := map[netip.Prefix]bool{}
	for i, t := range v.Prefixes {
		p, err := netip.ParsePrefix(t.Prefix)
		if err != nil || p != p.Masked() {
			return fmt.Errorf("%w: %s.prefixes[%d]: prefix %q must be a prefix without host bits", ErrForm, at, i, t.Prefix)
		}
		if p.Bits() == 0 {
			return fmt.Errorf("%w: %s.prefixes[%d]: a default route is not a VIP prefix", ErrForm, at, i)
		}
		if seen[p] {
			return fmt.Errorf("%w: %s.prefixes[%d]: duplicate prefix %s", ErrForm, at, i, p)
		}
		seen[p] = true
		if t.Host != "" {
			h, err := netip.ParseAddr(t.Host)
			if err != nil || !p.Contains(h) {
				return fmt.Errorf("%w: %s.prefixes[%d]: host %q must be an address inside %s", ErrForm, at, i, t.Host, p)
			}
		}
	}
	return validASNs(at+".asns", v.ASNs)
}

func (f Form) validateOutages() error {
	keys, names := make([]string, len(f.Outages)), make([]string, len(f.Outages))
	for i, o := range f.Outages {
		keys[i], names[i] = o.Key, o.Name
	}
	if err := validateInstances("outage", "outage", keys, names); err != nil {
		return err
	}
	for i, o := range f.Outages {
		if err := o.validate(fmt.Sprintf("outage[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

func (o FormOutage) validate(at string) error {
	if err := validInt(at+".min_prefixes", o.MinPrefixes, 0, 10000); err != nil {
		return err
	}
	if o.MinPrefixes == "1" {
		return fmt.Errorf("%w: %s.min_prefixes cannot be below 2 (one noisy prefix is not an incident)", ErrForm, at)
	}
	if err := validDuration(at+".window", o.Window, 0, 24*time.Hour); err != nil {
		return err
	}
	if err := numberField(at+".loss_pct", o.LossPct, 0, 100); err != nil {
		return err
	}
	if o.RTTMs != "" {
		v, err := strconv.ParseFloat(o.RTTMs, 64)
		if err != nil || v < 0 {
			return fmt.Errorf("%w: %s.rtt_ms %q must be zero or positive", ErrForm, at, o.RTTMs)
		}
	}
	if err := validDuration(at+".interval", o.Interval, 0, 24*time.Hour); err != nil {
		return err
	}
	if err := validInt(at+".max_targets", o.MaxTargets, 0, 10000); err != nil {
		return err
	}
	return validASNs(at+".ignore_asns", o.IgnoreASNs)
}
