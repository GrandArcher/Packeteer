package mikrotik

import (
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

const labBase = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
bgp:
  neighbors:
    - {address: 192.0.2.1}
sources:
  - type: static
    name: lab-sflow
    config:
      targets:
        - {prefix: 198.51.100.0/24, host: 198.51.100.1}
`

const labRouter = `offload_aware:
  enabled: true
  routers:
    - neighbor: 192.0.2.1
      profile: mikrotik-l3hw-lpm
      reader: routeros
      model: ccr2216
      volume_source: lab-sflow
      url: https://192.0.2.254
      username_env: PK_L3HW_USER
      password_env: PK_L3HW_PASSWORD
`

// The profile is selectable by its ID in a config, and its router settings
// are checked when the file is parsed.
func TestProfileIsRegisteredWithItsRouterChecks(t *testing.T) {
	cfg, err := config.Parse([]byte(labBase + labRouter))
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.OffloadAware.Routers[0]
	if cfg.Mode != config.ModeObserve || cfg.OffloadAware.Run != config.OffloadRunDryRun {
		t.Fatalf("mode %s run %s", cfg.Mode, cfg.OffloadAware.Run)
	}
	if o := OptionsOf(r); o.Model != CCR2216 || o.VolumeSource != "lab-sflow" {
		t.Errorf("options = %+v", o)
	}
	if rc := RESTConfig(r); rc.URL != "https://192.0.2.254" || rc.UsernameEnv != "PK_L3HW_USER" || rc.PasswordEnv != "PK_L3HW_PASSWORD" {
		t.Errorf("rest = %+v", rc)
	}
	for _, tc := range []struct{ from, to, want string }{
		{"reader: routeros", "reader: static", "needs reader: routeros"},
		{"model: ccr2216", "model: ccr9999", `unknown model "ccr9999"`},
		{"url: https://192.0.2.254", "url: http://192.0.2.254", "must be https"},
		{"      password_env: PK_L3HW_PASSWORD\n", "", "username_env and password_env are required"},
		{"volume_source: lab-sflow", "volume_source: nope", `"nope" is not a sources entry`},
	} {
		_, err := config.Parse([]byte(labBase + strings.Replace(labRouter, tc.from, tc.to, 1)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s -> %s: %v, want %q", tc.from, tc.to, err, tc.want)
		}
	}
	// A block that is not enabled runs nothing and is not checked.
	off := strings.Replace(labRouter, "enabled: true", "enabled: false", 1)
	off = strings.Replace(off, "model: ccr2216", "model: ccr9999", 1)
	if _, err := config.Parse([]byte(labBase + off)); err != nil {
		t.Errorf("disabled block: %v", err)
	}
}
