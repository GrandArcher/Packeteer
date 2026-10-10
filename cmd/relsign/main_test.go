package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/upgrade"
)

func TestSignThenVerify(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"keygen"}, func(string) string { return "" }, &out); err != nil {
		t.Fatal(err)
	}
	var pub, priv string
	for _, l := range strings.Split(out.String(), "\n") {
		if v, ok := strings.CutPrefix(l, "public_key: "); ok {
			pub = v
		}
		if v, ok := strings.CutPrefix(l, "private_key: "); ok {
			priv = v
		}
	}
	dir := t.TempDir()
	amd, arm := filepath.Join(dir, "packeteer-linux-amd64"), filepath.Join(dir, "packeteer-linux-arm64")
	for _, f := range []string{amd, arm} {
		if err := os.WriteFile(f, []byte("bin "+f), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := func(k string) string {
		if k == "PACKETEER_RELEASE_KEY" {
			return priv
		}
		return ""
	}
	if err := run([]string{"sign", dir, amd, arm}, env, &out); err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	sig, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if err := upgrade.VerifySignature(pub, sums, sig); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sums), "  packeteer-linux-amd64\n") || strings.Contains(string(sums), dir) {
		t.Fatalf("sums = %q", sums)
	}
	if strings.Contains(out.String(), priv+"\n") && strings.Count(out.String(), priv) > 1 {
		t.Fatal("the private key was printed by sign")
	}
	if err := run([]string{"sign", dir, amd}, func(string) string { return "" }, &out); err == nil {
		t.Fatal("signed without a key")
	}
}
