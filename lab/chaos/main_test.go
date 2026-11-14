package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestVtyshArgs(t *testing.T) {
	got := vtyshArgs(bgpCommand("neighbor 192.0.2.10 shutdown"))
	want := []string{"compose", "exec", "-T", "edge", "vtysh",
		"-c", "configure terminal", "-c", "router bgp 64512", "-c", "neighbor 192.0.2.10 shutdown", "-c", "end"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
}

func TestProbesReplacesStateFile(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.yaml")
	if err := os.WriteFile(state, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := compose{labDir: dir}
	if err := c.Probes(filepath.Join("..", "..", probesDown)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", probesDown))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("state.yaml = %q", got)
	}
	// The container's prober runs as another user and must read it.
	if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v err %v", fi.Mode(), err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
	if err := c.Probes(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing probe file accepted")
	}
}
