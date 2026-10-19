package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/herd"
)

func herdCmd(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), append([]string{"herd"}, args...), noEnv, &out, &errOut)
	return code, out.String(), errOut.String()
}

func writeHerdConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(cfg, []byte(herdYAML(dir)), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestHerdEntryPrintsASignedEntry(t *testing.T) {
	cfg := writeHerdConfig(t)
	keyFile := filepath.Join(filepath.Dir(cfg), "node.key")

	code, _, errOut := herdCmd("entry", "-config", cfg, "-url", "https://192.0.2.30:9444")
	if code != 1 || !strings.Contains(errOut, "start the controller once") {
		t.Fatalf("without a key: code %d: %s", code, errOut)
	}
	if _, err := os.Stat(keyFile); err == nil {
		t.Fatal("herd entry created a key")
	}

	node, err := herd.LoadNode(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := herdCmd("entry", "-config", cfg, "-url", "https://192.0.2.30:9444", "-valid", "720h",
		"-statement-url", "https://example.net/id.json", "-statement-sha256", strings.Repeat("0a", 32), "-rsc-url", "https://example.net/id.rsc")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	e, err := herd.CheckEntry([]byte(out), time.Now())
	if err != nil {
		t.Fatalf("printed entry does not verify: %v\n%s", err, out)
	}
	if e.ASN != 64512 || e.Signer != node.PublicKey() || e.Nodes[0].URL != "https://192.0.2.30:9444" || e.RetentionDays != 90 ||
		len(e.Classes) != 1 || e.Classes[0] != "measurements" || e.Identity == nil || e.Identity.RSCURL != "https://example.net/id.rsc" {
		t.Errorf("entry = %+v", e)
	}
	if d := e.Expires.Sub(e.Issued); d != 720*time.Hour {
		t.Errorf("valid for %s", d)
	}
}

func TestHerdEntryRefusals(t *testing.T) {
	cfg := writeHerdConfig(t)
	if _, err := herd.LoadNode(filepath.Join(filepath.Dir(cfg), "node.key")); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no url":           {[]string{"-config", cfg}, "-url is required"},
		"loopback url":     {[]string{"-config", cfg, "-url", "https://127.0.0.1:9444"}, "not a routable address"},
		"http url":         {[]string{"-config", cfg, "-url", "http://192.0.2.30:9444"}, "https"},
		"too long":         {[]string{"-config", cfg, "-url", "https://192.0.2.30:9444", "-valid", "9000h"}, "within"},
		"bad node":         {[]string{"-config", cfg, "-url", "https://192.0.2.30:9444", "-node", "nokey"}, "-node"},
		"partial identity": {[]string{"-config", cfg, "-url", "https://192.0.2.30:9444", "-rsc-url", "https://example.net/x"}, "identity"},
		"missing config":   {[]string{"-config", filepath.Join(t.TempDir(), "none.yaml"), "-url", "https://192.0.2.30:9444"}, "none.yaml"},
		"unknown subcmd":   {nil, "usage"},
	} {
		args := append([]string{"entry"}, tc.args...)
		if tc.args == nil {
			args = []string{"bogus"}
		}
		code, out, errOut := herdCmd(args...)
		if code == 0 || out != "" || !strings.Contains(errOut, tc.want) {
			t.Errorf("%s: code %d out %q err %q, want %q", name, code, out, errOut, tc.want)
		}
	}
}

func TestHerdEntryNeedsServingHerd(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	text := strings.Replace(herdYAML(t.TempDir()), "  listen: 127.0.0.1:0\n  peers:\n    - url: https://192.0.2.30:9444\n      key: "+herdPeerKey+"\n", "  preview_only: true\n", 1)
	if err := os.WriteFile(cfg, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := herdCmd("entry", "-config", cfg, "-url", "https://192.0.2.30:9444")
	if code != 1 || !strings.Contains(errOut, "not serving") {
		t.Errorf("code %d: %s", code, errOut)
	}
}

// hubDir writes entries named by asn into a new directory.
func hubDir(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func hubEntry(t *testing.T, asn uint32, url string, valid time.Duration, issuedAgo time.Duration) (*herd.Node, []byte) {
	t.Helper()
	n, err := herd.LoadNode(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, err := n.SignEntry(herd.Entry{
		ASN: asn, Nodes: []herd.EntryNode{{Key: n.PublicKey(), URL: url}}, RetentionDays: 90,
		Classes: []string{"measurements"}, Issued: now.Add(-issuedAgo), Expires: now.Add(-issuedAgo).Add(valid),
	})
	if err != nil {
		t.Fatal(err)
	}
	return n, raw
}

func TestHubCheck(t *testing.T) {
	_, e1 := hubEntry(t, 64501, "https://192.0.2.31:9444", 30*24*time.Hour, time.Hour)
	_, e2 := hubEntry(t, 64502, "https://192.0.2.32:9444", 30*24*time.Hour, time.Hour)
	_, old := hubEntry(t, 64503, "https://192.0.2.33:9444", 24*time.Hour, 48*time.Hour)
	list := filepath.Join(t.TempDir(), "herd.json")

	t.Run("valid entries build the list", func(t *testing.T) {
		dir := hubDir(t, map[string][]byte{"64502.json": e2, "64501.json": e1})
		code, out, errOut := herdCmd("hub-check", "-list", list, dir)
		if code != 0 || !strings.Contains(out, "2 entries ok") {
			t.Fatalf("code %d out %q err %q", code, out, errOut)
		}
		raw, _ := os.ReadFile(list)
		entries, rejected, err := herd.ParseHubList(raw, time.Now())
		if err != nil || rejected != 0 || len(entries) != 2 || entries[0].ASN != 64501 || entries[1].ASN != 64502 {
			t.Errorf("list = %+v rejected %d err %v", entries, rejected, err)
		}
		var l herd.HubList
		if err := json.Unmarshal(raw, &l); err != nil || l.Schema != herd.HubSchema {
			t.Errorf("list header: %+v %v", l, err)
		}
	})

	t.Run("failures name the file", func(t *testing.T) {
		_, sameURL := hubEntry(t, 64504, "https://192.0.2.31:9444", time.Hour*24, time.Hour)
		tampered := []byte(strings.Replace(string(e2), "64502", "64509", 1))
		dir := hubDir(t, map[string][]byte{
			"64501.json": e1, "64502.json": tampered, "64503.json": old, "64504.json": sameURL, "99999.json": e2,
		})
		code, _, errOut := herdCmd("hub-check", dir)
		if code != 1 {
			t.Fatalf("code %d", code)
		}
		for _, want := range []string{
			"64502.json: entry asn 64509: signature does not verify",
			"64503.json: entry asn 64503: expired",
			"64504.json: a node url is also in 64501.json",
			"99999.json: entry for asn 64502 must be named 64502.json",
		} {
			if !strings.Contains(errOut, want) {
				t.Errorf("stderr missing %q:\n%s", want, errOut)
			}
		}
	})

	t.Run("only json files are entries", func(t *testing.T) {
		dir := hubDir(t, map[string][]byte{"64501.json": e1, "README.md": []byte("x"), ".gitkeep": nil, ".hidden.json": []byte("x")})
		if err := os.Mkdir(filepath.Join(dir, "docs.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		code, out, errOut := herdCmd("hub-check", dir)
		if code != 0 || !strings.Contains(out, "1 entries ok") {
			t.Errorf("code %d out %q err %q", code, out, errOut)
		}
	})

	t.Run("one key under two ASNs", func(t *testing.T) {
		n, e := hubEntry(t, 64501, "https://192.0.2.31:9444", 30*24*time.Hour, time.Hour)
		now := time.Now()
		second, err := n.SignEntry(herd.Entry{
			ASN: 64502, Nodes: []herd.EntryNode{{Key: n.PublicKey(), URL: "https://192.0.2.77:9444"}}, RetentionDays: 90,
			Classes: []string{"measurements"}, Issued: now, Expires: now.Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		code, _, errOut := herdCmd("hub-check", hubDir(t, map[string][]byte{"64501.json": e, "64502.json": second}))
		if code != 1 || !strings.Contains(errOut, "64502.json: a node key is also in 64501.json") {
			t.Errorf("code %d: %s", code, errOut)
		}
	})

	t.Run("prune removes only expired entries", func(t *testing.T) {
		dir := hubDir(t, map[string][]byte{"64501.json": e1, "64503.json": old})
		code, out, errOut := herdCmd("hub-check", "-prune", dir)
		if code != 0 || !strings.Contains(out, "pruned 64503.json") || !strings.Contains(out, "1 entries ok, 1 pruned") {
			t.Fatalf("code %d out %q err %q", code, out, errOut)
		}
		if _, err := os.Stat(filepath.Join(dir, "64503.json")); !os.IsNotExist(err) {
			t.Error("expired file kept")
		}
		if _, err := os.Stat(filepath.Join(dir, "64501.json")); err != nil {
			t.Error("valid file removed")
		}
	})

	t.Run("prune keeps a broken entry and fails", func(t *testing.T) {
		tampered := []byte(strings.Replace(string(e2), "64502", "64509", 1))
		dir := hubDir(t, map[string][]byte{"64502.json": tampered})
		if code, _, _ := herdCmd("hub-check", "-prune", dir); code != 1 {
			t.Errorf("code %d", code)
		}
		if _, err := os.Stat(filepath.Join(dir, "64502.json")); err != nil {
			t.Error("broken file removed")
		}
	})

	t.Run("usage", func(t *testing.T) {
		if code, _, _ := herdCmd("hub-check"); code != 2 {
			t.Errorf("code %d", code)
		}
	})
}
