package readonly

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllowlistMatchesWholeCommands(t *testing.T) {
	a := NewAllowlist(`show bgp neighbors json`, `show route-map `+Name+` json`)
	for _, ok := range []string{"show bgp neighbors json", "show route-map packeteer-in json", "show route-map 64512:in_v4.x json"} {
		if err := a.Check(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "show bgp neighbors", "show bgp neighbors json ", " show bgp neighbors json",
		"show bgp neighbors json\nconfigure terminal", "show bgp neighbors json\x00write memory",
		"show route-map a b json", "show route-map a;b json", "show route-map " + strings.Repeat("x", 64) + " json",
		"configure terminal",
	} {
		if err := a.Check(bad); !errors.Is(err, ErrRefused) {
			t.Errorf("%q = %v, want ErrRefused", bad, err)
		}
	}
}

func TestPathFromTheEnvironment(t *testing.T) {
	env := map[string]string{"SOCK": "/run/frr/bgpd.vty", "REL": "run/bgpd.vty"}
	getenv := func(k string) string { return env[k] }
	if p, err := Path(getenv, "socket_env", "SOCK", false); err != nil || p != "/run/frr/bgpd.vty" {
		t.Fatalf("Path = %q, %v", p, err)
	}
	for name, want := range map[string]string{
		"":      "socket_env",
		"UNSET": "UNSET is not set",
		"REL":   "absolute path",
		"1BAD":  "not an environment variable name",
	} {
		_, err := Path(getenv, "socket_env", name, false)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", name, err, want)
		}
		if strings.Contains(errString(err), "run/bgpd.vty") {
			t.Errorf("%q: the error shows the path: %v", name, err)
		}
	}
	// The config editor checks the name only.
	if _, err := Path(getenv, "socket_env", "UNSET", true); err != nil {
		t.Errorf("check only, unset: %v", err)
	}
	if _, err := Path(getenv, "socket_env", "1BAD", true); err == nil {
		t.Error("check only accepted a malformed name")
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestDialAndScrubHideThePath(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "secret-name.vty")
	_, err := Dial(context.Background(), sock)
	if err == nil || strings.Contains(err.Error(), "secret-name") || strings.Contains(err.Error(), dir) {
		t.Fatalf("Dial error = %v", err)
	}
	if !strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("Dial error lost its cause: %v", err)
	}
	_, err = os.Open(filepath.Join(dir, "secret-name.conf"))
	if s := Scrub(err).Error(); strings.Contains(s, "secret-name") || !strings.Contains(s, "no such file") {
		t.Errorf("Scrub = %q", s)
	}
	other := errors.New("plain")
	if Scrub(other) != other {
		t.Error("Scrub changed an error without a path")
	}
}
