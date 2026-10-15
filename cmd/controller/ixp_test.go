package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const ixpObserveYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
ixp: {}
`

func TestIXPModeBuildsNoRIB(t *testing.T) {
	cfg := mustParse(t, ixpObserveYAML)
	if cfg.IXP == nil || len(cfg.BGP.Neighbors) != 0 {
		t.Fatalf("ixp %v neighbors %d", cfg.IXP, len(cfg.BGP.Neighbors))
	}
	view, err := newRIB(cfg, nil)
	if err != nil || view != nil {
		t.Fatalf("IXP mode with no neighbors built a RIB view: view=%v err=%v", view, err)
	}
}

func TestIXPChangeNeedsRestart(t *testing.T) {
	base := strings.Replace(ixpObserveYAML, "ixp: {}\n", "", 1)
	cur := mustParse(t, base)
	next := mustParse(t, ixpObserveYAML)
	restart, online := classify(cur, next)
	if !slices.Contains(restart, "ixp") || len(online) != 0 {
		t.Fatalf("restart %v online %v, want only ixp", restart, online)
	}
	if _, err := planReload(cur, next, nil); err == nil || !strings.Contains(err.Error(), "restart required: changed ixp") {
		t.Fatalf("planReload: %v", err)
	}
}

func TestRunIXPCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(ixpObserveYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	if code := run(t.Context(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %s", code, errOut.String())
	}
	for _, want := range []string{
		"mode: observe",
		"ixp: on (observe-only, never announces)",
		"announce: disabled",
		"bgp: disabled (no bgp.neighbors)",
		"check: ok",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}

	bad := strings.Replace(ixpObserveYAML, "mode: observe", "mode: inject", 1) +
		"announcer: {type: gobgp}\npacketeer_community: \"64512:666\"\nlocal_pref: 200\nhold_time: 15m\n" +
		"thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}\nallowlist: {prefixes: [198.51.100.0/24]}\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run(t.Context(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 1 {
		t.Fatalf("exit %d, want 1; stdout %s stderr %s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"ixp forbids mode inject", "ixp forbids announcer"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr missing %q:\n%s", want, errOut.String())
		}
	}
}
