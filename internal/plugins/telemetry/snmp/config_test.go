package snmp

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func mustNew(t *testing.T, yml string, env map[string]string) *Collector {
	t.Helper()
	c, err := plugin.ConfigFromYAML(yml)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(c, plugin.Env{
		Name:      "snmp",
		Logger:    discardLog(),
		Getenv:    envOf(env),
		Providers: []string{"transit-a", "transit-b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Collector)
}

const baseYAML = `
interval: 30s
timeout: 1s
retries: 0
hosts:
  - name: edge
    address: 192.0.2.254
    version: 2c
    community_env: PACKETEER_SNMP_COMMUNITY
providers:
  - name: transit-a
    host: edge
    interface: ether1
    commit_mbps: 1000
    billing_day: 1
    percentile: greater_separate
`

func TestConfigAcceptsEnvCredential(t *testing.T) {
	secret := "lab-community-value"
	c := mustNew(t, baseYAML, map[string]string{"PACKETEER_SNMP_COMMUNITY": secret})
	if c.hosts[0].community != secret {
		t.Fatal("community was not read from the environment")
	}
	rows, err := c.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.ToLower(rows[0].Provider + rows[0].Error + rows[0].Host)
	if strings.Contains(blob, secret) || strings.Contains(blob, "community") {
		t.Fatalf("snapshot leaked credential material: %+v", rows)
	}
	if rows[0].CommitMbps != 1000 || rows[0].Mode != plugin.PercentileGreaterSeparate || rows[0].Samples != 0 {
		t.Fatalf("snapshot = %+v", rows[0])
	}
}

func TestConfigRejects(t *testing.T) {
	secret := "lab-community-value"
	env := map[string]string{
		"PACKETEER_SNMP_COMMUNITY": secret,
		"PACKETEER_SNMP_USER":      "packeteer",
		"PACKETEER_SNMP_AUTH":      "short",
		"PACKETEER_SNMP_PRIV":      "another-passphrase",
	}
	tests := []struct {
		name string
		yaml string
		env  map[string]string
		want string
	}{
		{"unknown field", "interval: 30s\nbogus: 1\n", env, "bogus"},
		{"literal community", "hosts:\n  - name: e\n    address: 192.0.2.254\n    version: 2c\n    community: " + secret + "\nproviders:\n  - name: transit-a\n    host: e\n    interface: ether1\n    commit_mbps: 1\n    billing_day: 1\n    percentile: separate\n", env, "field community not found"},
		{"empty env", baseYAML, map[string]string{}, "empty or unset"},
		{"community in the value position", strings.Replace(baseYAML, "PACKETEER_SNMP_COMMUNITY", secret, 1), env, "must be an environment variable name"},
		{"bad percentile", strings.Replace(baseYAML, "greater_separate", "average", 1), env, "percentile"},
		{"billing day", strings.Replace(baseYAML, "billing_day: 1", "billing_day: 31", 1), env, "billing_day"},
		{"commit", strings.Replace(baseYAML, "commit_mbps: 1000", "commit_mbps: 0", 1), env, "commit_mbps"},
		{"unknown provider", strings.Replace(baseYAML, "transit-a", "transit-z", 1), env, "not a configured provider"},
		{"unknown host", strings.Replace(baseYAML, "host: edge", "host: missing", 1), env, "not in hosts"},
		{"interval", strings.Replace(baseYAML, "interval: 30s", "interval: 1s", 1), env, "interval"},
		{"version 1", strings.Replace(baseYAML, "version: 2c", "version: 1", 1), env, "version"},
		{"v3 short auth", `
hosts:
  - name: edge
    address: 192.0.2.254
    version: 3
    username_env: PACKETEER_SNMP_USER
    security_level: authPriv
    auth_protocol: SHA256
    auth_env: PACKETEER_SNMP_AUTH
    priv_protocol: AES
    priv_env: PACKETEER_SNMP_PRIV
providers:
  - name: transit-a
    host: edge
    interface: ether1
    commit_mbps: 1000
    billing_day: 1
    percentile: separate
`, env, "at least 8"},
		{"v2c with v3 field", `
hosts:
  - name: edge
    address: 192.0.2.254
    version: 2c
    community_env: PACKETEER_SNMP_COMMUNITY
    username_env: PACKETEER_SNMP_USER
providers:
  - name: transit-a
    host: edge
    interface: ether1
    commit_mbps: 1
    billing_day: 1
    percentile: separate
`, env, "community_env only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := plugin.ConfigFromYAML(tt.yaml)
			if err != nil {
				t.Fatal(err)
			}
			_, err = New(c, plugin.Env{Logger: discardLog(), Getenv: envOf(tt.env), Providers: []string{"transit-a", "transit-b"}})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "short") || strings.Contains(err.Error(), "another-passphrase") || strings.Contains(err.Error(), "lab-community-value") && tt.name != "community in the value position" && tt.name != "literal community" {
				t.Fatalf("error leaked a secret: %v", err)
			}
		})
	}
}

func TestConfigV3BuildsSecurity(t *testing.T) {
	c := mustNew(t, `
interval: 30s
timeout: 1s
retries: 0
hosts:
  - name: edge
    address: 192.0.2.254
    version: v3
    username_env: PACKETEER_SNMP_USER
    security_level: authPriv
    auth_protocol: sha256
    auth_env: PACKETEER_SNMP_AUTH
    priv_protocol: aes256
    priv_env: PACKETEER_SNMP_PRIV
    context_name: lab
providers:
  - name: transit-a
    host: edge
    interface: "5"
    commit_mbps: 100
    billing_day: 15
    percentile: greater
`, map[string]string{
		"PACKETEER_SNMP_USER": "packeteer",
		"PACKETEER_SNMP_AUTH": "auth-passphrase",
		"PACKETEER_SNMP_PRIV": "priv-passphrase",
	})
	h := c.hosts[0]
	if h.version != "3" || h.level != "authPriv" || h.authProto != "SHA256" || h.privProto != "AES256" || h.username != "packeteer" || h.context != "lab" {
		t.Fatalf("host = %+v", h)
	}
	if !strings.Contains(h.authPass, "auth") || h.community != "" {
		t.Fatal("v3 host kept a v2c community or dropped the auth passphrase")
	}
	g := &gosnmp.GoSNMP{}
	if err := applySecurity(g, h); err != nil {
		t.Fatal(err)
	}
	if g.Version != gosnmp.Version3 || g.MsgFlags != gosnmp.AuthPriv || g.ContextName != "lab" {
		t.Fatalf("client = %+v", g)
	}
	sp, ok := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok || sp.UserName != "packeteer" || sp.AuthenticationProtocol != gosnmp.SHA256 || sp.PrivacyProtocol != gosnmp.AES256 || sp.AuthenticationPassphrase != "auth-passphrase" {
		t.Fatalf("security = %#v", g.SecurityParameters)
	}
}
