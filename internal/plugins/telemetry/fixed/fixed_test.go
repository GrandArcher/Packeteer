package fixed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func build(t *testing.T, y string, providers []string) plugin.Telemetry {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(c, plugin.Env{Providers: providers})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSnapshot(t *testing.T) {
	s := build(t, `
providers:
  - {name: transit-a, commit_mbps: 100, usage_mbps: 150}
  - {name: transit-b, commit_mbps: 100, usage_mbps: 20}
`, []string{"transit-a", "transit-b"})
	rows, err := s.Snapshot(context.Background())
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	mbps, ok := rows[0].BillableMbps()
	if !ok || mbps != 150 || rows[0].Provider != "transit-a" || rows[0].Updated.IsZero() {
		t.Fatalf("row %+v mbps %v ok %v", rows[0], mbps, ok)
	}
	if names := s.(interface{ ProviderNames() []string }).ProviderNames(); len(names) != 2 || names[0] != "transit-a" {
		t.Fatalf("names %v", names)
	}
}

func TestFileReread(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.yaml")
	body := "providers:\n  - {name: transit-a, commit_mbps: 100, usage_mbps: 150}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s := build(t, "file: "+path+"\n", []string{"transit-a"})
	rows, err := s.Snapshot(context.Background())
	if err != nil || len(rows) != 1 || rows[0].UsageMbps != 150 {
		t.Fatalf("first %+v %v", rows, err)
	}
	next := "providers:\n  - {name: transit-a, commit_mbps: 100, usage_mbps: 20}\n"
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, err = s.Snapshot(context.Background())
	if err != nil || len(rows) != 1 || rows[0].UsageMbps != 20 {
		t.Fatalf("reread %+v %v", rows, err)
	}
}

func TestRejects(t *testing.T) {
	cases := []struct{ y, want string }{
		{"", "set providers or file"},
		{"providers:\n  - {name: transit-a, commit_mbps: 0, usage_mbps: 1}", "commit_mbps"},
		{"providers:\n  - {name: transit-a, commit_mbps: 10, usage_mbps: -1}", "usage_mbps"},
		{"providers:\n  - {name: no-such, commit_mbps: 10, usage_mbps: 1}", "not configured"},
		{"providers:\n  - {name: transit-a, commit_mbps: 10, usage_mbps: 1}\n  - {name: transit-a, commit_mbps: 10, usage_mbps: 1}", "duplicate"},
		{"nope: 1", "not found"},
	}
	for _, tc := range cases {
		c, err := plugin.ConfigFromYAML(tc.y)
		if err != nil {
			t.Fatal(err)
		}
		_, err = New(c, plugin.Env{Providers: []string{"transit-a"}})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: got %v", tc.y, err)
		}
	}
}

func TestCancelledSnapshot(t *testing.T) {
	s := build(t, "providers:\n  - {name: a, commit_mbps: 10, usage_mbps: 1}\n", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Snapshot(ctx); err == nil {
		t.Fatal("cancelled context returned rows")
	}
}
