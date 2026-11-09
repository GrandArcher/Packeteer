package config

import (
	"strings"
	"testing"
	"time"
)

const feedBlock = `
external_policy:
  enabled: true
  listen: 192.0.2.10:9443
  cert_file: /etc/packeteer/tls/feed.crt
  key_file: /etc/packeteer/tls/feed.key
`

func TestExternalPolicyDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExternalPolicyOn() || cfg.ExternalPolicy != nil {
		t.Fatalf("feed on without a block: %+v", cfg.ExternalPolicy)
	}
	cfg, err = Parse([]byte(validYAML + feedBlock))
	if err != nil {
		t.Fatal(err)
	}
	e := cfg.ExternalPolicy
	if !cfg.ExternalPolicyOn() || e.TokenEnv != DefaultPolicyTokenEnv || e.TTL != 90*time.Second {
		t.Fatalf("defaults: %+v (probe interval 30s, want ttl 90s)", e)
	}
	off, err := Parse([]byte(validYAML + strings.Replace(feedBlock, "enabled: true", "enabled: false", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if off.ExternalPolicyOn() {
		t.Fatal("enabled: false is on")
	}
}

// With the feed enabled, inject runs without an announcer; with neither it
// is refused, as before.
func TestExternalPolicyInjectWithoutAnnouncer(t *testing.T) {
	noAnn := strings.Replace(injectYAML, "announcer:\n  type: gobgp\n", "", 1)
	if _, err := Parse([]byte(noAnn)); err == nil || !strings.Contains(err.Error(), "requires an announcer or external_policy.enabled") {
		t.Fatalf("inject with neither: %v", err)
	}
	if _, err := Parse([]byte(noAnn + feedBlock)); err != nil {
		t.Fatalf("inject with the feed only: %v", err)
	}
	if _, err := Parse([]byte(noAnn + strings.Replace(feedBlock, "enabled: true", "enabled: false", 1))); err == nil {
		t.Fatal("inject with a disabled feed and no announcer accepted")
	}
	if _, err := Parse([]byte(strings.Replace(noAnn, "bgp:\n  neighbors:\n    - address: 192.0.2.1\n", "", 1) + feedBlock)); err == nil || !strings.Contains(err.Error(), "bgp.neighbors entry, or rib_sources") {
		t.Fatalf("feed only with no RIB view: %v", err)
	}
}

// A feed-only inject config can learn the RIB over BMP alone (#237).
func TestExternalPolicyBMPAlone(t *testing.T) {
	noBGP := strings.Replace(injectYAML, "bgp:\n  neighbors:\n    - address: 192.0.2.1\n", "", 1)
	noBGP = strings.Replace(noBGP, "    next_hop: 192.0.2.1\n", "    next_hop: 192.0.2.1\n    bmp: only\n", 1)
	src := "rib_sources:\n  - type: bmp\n    config:\n      routers: [192.0.2.254]\n"
	feedOnly := strings.Replace(noBGP, "announcer:\n  type: gobgp\n", "", 1) + src + feedBlock
	if _, err := Parse([]byte(feedOnly)); err != nil {
		t.Fatalf("feed only over BMP alone: %v", err)
	}
	if _, err := Parse([]byte(noBGP + src + feedBlock)); err == nil || !strings.Contains(err.Error(), "announcer requires bgp.neighbors") {
		t.Fatalf("announcer without an iBGP session: %v", err)
	}
}

func TestExternalPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		old, new, want string
	}{
		{"listen: 192.0.2.10:9443", "listen: 192.0.2.10", "external_policy.listen"},
		{"  key_file: /etc/packeteer/tls/feed.key\n", "", "cert_file and key_file"},
		{"listen:", "token_env: \"BAD-NAME\"\n  listen:", "token_env"},
		{"listen:", "ttl: 89s\n  listen:", "at least three probe intervals"},
	} {
		// A disabled block is checked too, so enabling it online cannot
		// fail on a key a restart would refuse.
		for _, block := range []string{feedBlock, strings.Replace(feedBlock, "enabled: true", "enabled: false", 1)} {
			_, err := Parse([]byte(validYAML + edit(t, block, tc.old, tc.new)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%q -> %q: %v, want %q", tc.old, tc.new, err, tc.want)
			}
		}
	}
}

func TestIXPRefusesExternalPolicy(t *testing.T) {
	base := validYAML + "ixp: {}\n"
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatalf("ixp without the feed: %v", err)
	}
	if _, err := Parse([]byte(base + feedBlock)); err == nil || !strings.Contains(err.Error(), "ixp forbids external_policy") {
		t.Fatalf("ixp with the feed: %v", err)
	}
}

// Synthesized sub-ranges are not in the learned RIB; the feed would list
// them, so the two blocks are refused together, enabled or not.
func TestExternalPolicyRefusesSynthesize(t *testing.T) {
	for _, synth := range []string{
		synthBlock,
		"synthesize: {covering_prefixes: [198.51.100.0/24]}\n",
	} {
		_, err := Parse([]byte(injectYAML + synth + feedBlock))
		if err == nil || !strings.Contains(err.Error(), "external_policy cannot be combined with synthesize") {
			t.Fatalf("feed with synthesize %q: %v", synth, err)
		}
	}
	if _, err := Parse([]byte(injectYAML + synthBlock)); err != nil {
		t.Fatalf("synthesize without the feed: %v", err)
	}
}
