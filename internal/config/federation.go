package config

import (
	"math"
	"strconv"
	"time"
)

// Multi-POP limits (#30).
const (
	// MaxInterDCRTT bounds a configured inter-DC round-trip time.
	MaxInterDCRTT = 10 * time.Second
	// MaxGlobalCommitMbps matches the telemetry commit cap.
	MaxGlobalCommitMbps = 100000000
)

// validateFederation checks routing domains, inter-DC RTT, global
// commits, and the federation transport (#30).
func (c *Config) validateFederation(add func(string, ...any)) {
	fed := c.Federation != nil
	if c.Domain != "" && !validName(c.Domain) {
		add("domain %q must be 1-64 characters of letters, digits, '_', '.' or '-', starting with a letter or digit", c.Domain)
	}
	if c.Instance != "" && !validName(c.Instance) {
		add("instance %q must be 1-64 characters of letters, digits, '_', '.' or '-', starting with a letter or digit", c.Instance)
	}
	if fed {
		if c.Domain == "" {
			add("federation requires domain (this instance's routing domain)")
		}
		if c.Federation.Type == "" {
			add("federation.type is required")
		}
	}
	for d, rtt := range c.InterDCRTT {
		switch {
		case !validName(d):
			add("inter_dc_rtt: domain %q is not a valid name", d)
		case d == c.Domain:
			add("inter_dc_rtt: %s is this instance's own domain", d)
		case rtt < 0 || rtt > MaxInterDCRTT:
			add("inter_dc_rtt: %s %s must be between 0 and %s", d, rtt, MaxInterDCRTT)
		}
	}
	for i, p := range c.Providers {
		if !c.Remote(p) {
			continue
		}
		label := "providers[" + strconv.Itoa(i) + "] (" + p.Name + ")"
		if !fed {
			add("%s: domain %s is not this instance's domain %q; a provider in another domain needs federation", label, p.Domain, c.Domain)
		}
		if _, ok := c.InterDCRTT[p.Domain]; !ok {
			add("%s: inter_dc_rtt has no entry for domain %s", label, p.Domain)
		}
		if p.BMP != "" && p.BMP != BMPOff {
			add("%s: bmp does not apply to a provider in another domain (the peer there reports its route)", label)
		}
		if p.AddPath {
			add("%s: add_path does not apply to a provider in another domain (the peer there reports its route)", label)
		}
	}
	if len(c.GlobalCommits) > 0 && !fed {
		add("global_commit requires federation")
	}
	names := map[string]bool{}
	member := map[string]string{}
	providers := map[string]Provider{}
	for _, p := range c.Providers {
		providers[p.Name] = p
	}
	for i, g := range c.GlobalCommits {
		label := "global_commit[" + strconv.Itoa(i) + "]"
		if !validName(g.Name) {
			add("%s: name %q must be 1-64 characters of letters, digits, '_', '.' or '-', starting with a letter or digit", label, g.Name)
		} else {
			label += " (" + g.Name + ")"
			if names[g.Name] {
				add("%s: duplicate name", label)
			}
			names[g.Name] = true
		}
		if math.IsNaN(g.CommitMbps) || g.CommitMbps <= 0 || g.CommitMbps > MaxGlobalCommitMbps {
			add("%s: commit_mbps %v must be above 0 and at most %d", label, g.CommitMbps, MaxGlobalCommitMbps)
		}
		if len(g.Providers) < 2 {
			add("%s: needs at least two providers", label)
		}
		local := false
		for _, name := range g.Providers {
			p, ok := providers[name]
			if !ok {
				add("%s: provider %q is not configured", label, name)
				continue
			}
			if other, dup := member[name]; dup {
				add("%s: provider %s is already in global_commit %s", label, name, other)
			}
			member[name] = g.Name
			if !c.Remote(p) {
				local = true
			}
		}
		if !local {
			add("%s: needs at least one provider in this instance's domain", label)
		}
	}
}

func validName(s string) bool { return s != "" && validProviderGroup(s) }
