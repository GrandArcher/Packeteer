package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestDaemonHistorySurvivesRestart runs the controller twice on the same
// sqlite file (the mounted /var/lib/packeteer volume in the container).
// Probe rollups written by the first run are still there, and the second
// run adds to them. The fixed prober sends no packets.
func TestDaemonHistorySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "data", "packeteer.db")
	body := `mode: observe
asn: 64512
router_id: 192.0.2.10
http: {listen: ""}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
probe: {interval: 1s, timeout: 100ms, packets: 2}
probers:
  - type: fixed
    config:
      paths:
        - {provider: transit-a, rtt_ms: 40, loss_pct: 50}
        - {provider: transit-b, rtt_ms: 20}
sources:
  - type: static
    config: {targets: [{prefix: 198.51.100.0/24}]}
storage:
  type: sqlite
  config: {path: ` + db + `}
`
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	runOnce := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
		defer cancel()
		var out, errOut bytes.Buffer
		if code := run(ctx, []string{"-config", path}, noEnv, &out, &errOut); code != 0 {
			t.Fatalf("exit code %d\n%s", code, errOut.String())
		}
		if !strings.Contains(out.String(), "storage sqlite") {
			t.Fatalf("plugin summary missing storage:\n%s", out.String())
		}
	}
	probes := func() map[string]plugin.ProbeBucket {
		t.Helper()
		cfg, _ := plugin.ConfigFromYAML("path: " + db)
		s, err := sqlite.New(cfg, plugin.Env{})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if err := s.Start(ctx); err != nil {
			t.Fatal(err)
		}
		defer s.Stop(ctx)
		now := time.Now().UTC()
		h, err := s.Read(ctx, plugin.HistoryQuery{From: now.Add(-48 * time.Hour), To: now.Add(48 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]plugin.ProbeBucket{}
		for _, b := range h.Buckets {
			if prev, ok := out[b.Provider]; ok {
				b.Probes += prev.Probes
				b.Measured += prev.Measured
				b.LossSum += prev.LossSum
			}
			out[b.Provider] = b
		}
		return out
	}

	runOnce()
	first := probes()
	a, b := first["transit-a"], first["transit-b"]
	if a.Probes == 0 || b.Probes == 0 || a.LossSum != 50*float64(a.Measured) || b.RTTSumMs != 20*float64(b.Measured) {
		t.Fatalf("first run rollups = %+v", first)
	}
	runOnce()
	second := probes()
	if second["transit-a"].Probes <= a.Probes || second["transit-b"].Probes <= b.Probes {
		t.Fatalf("second run did not add to the stored rollups: first %+v second %+v", first, second)
	}
}
