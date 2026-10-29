package sinkcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTLS(t *testing.T) {
	if c, err := TLS(false, ""); c != nil || err != nil {
		t.Fatalf("off: %v %v", c, err)
	}
	if _, err := TLS(false, "/x.pem"); err == nil {
		t.Fatal("ca_file without tls must fail")
	}
	c, err := TLS(true, "")
	if err != nil || c == nil || c.RootCAs != nil {
		t.Fatalf("system roots: %v %v", c, err)
	}
	if _, err := TLS(true, "rel.pem"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative path: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := TLS(true, bad); err == nil || !strings.Contains(err.Error(), "no PEM") {
		t.Fatalf("junk PEM: %v", err)
	}
	if _, err := TLS(true, filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("missing file must fail")
	}
}

func TestCredentials(t *testing.T) {
	env := map[string]string{"U": "alice", "P": "pw"}
	get := func(k string) string { return env[k] }
	u, p, err := Credentials(get, "U", "P")
	if err != nil || u != "alice" || p != "pw" {
		t.Fatalf("got %q %q %v", u, p, err)
	}
	if u, p, err = Credentials(get, "", ""); err != nil || u != "" || p != "" {
		t.Fatalf("neither: %q %q %v", u, p, err)
	}
	for _, c := range [][2]string{{"U", ""}, {"", "P"}, {"U", "MISSING"}, {"bad name", "P"}} {
		if _, _, err := Credentials(get, c[0], c[1]); err == nil {
			t.Fatalf("%v must fail", c)
		}
	}
}
