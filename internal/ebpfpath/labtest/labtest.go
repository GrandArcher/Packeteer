// Package labtest is the root-only lab setup shared by the eBPF data path
// tests (#229). The tests that use it run in CI with sudo and skip
// everywhere else.
package labtest

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// RequireRoot skips the test unless it runs as root with the ip tool.
func RequireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (CI runs it with sudo)")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs the ip tool")
	}
}

// ip runs one ip command and fails the test with its output.
func ip(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// Veth creates a veth pair, both ends up, and removes it when the test
// ends. The first end gets addr (for example "192.0.2.1/24"). It returns
// the names of the two ends. Frames sent out of the first end leave through
// its egress hook and arrive on the second end.
func Veth(t *testing.T, addr string) (string, string) {
	t.Helper()
	a, b := "pkv0", "pkv1"
	_ = exec.Command("ip", "link", "del", a).Run()
	ip(t, "link", "add", a, "type", "veth", "peer", "name", b)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", a).Run() })
	ip(t, "addr", "add", addr, "dev", a)
	ip(t, "link", "set", a, "up")
	ip(t, "link", "set", b, "up")
	return a, b
}

// StaticNeighbor makes dst reachable on dev without ARP, so a UDP socket
// can send to it although nothing answers.
func StaticNeighbor(t *testing.T, dst, mac, dev string) {
	t.Helper()
	ip(t, "neigh", "replace", dst, "lladdr", mac, "dev", dev, "nud", "permanent")
}

// Tun creates a layer-3 tun device, which has no Ethernet header and so
// cannot take the eBPF path. It is removed when the test ends.
func Tun(t *testing.T) string {
	t.Helper()
	name := "pkt0"
	_ = exec.Command("ip", "link", "del", name).Run()
	if out, err := exec.Command("ip", "tuntap", "add", "dev", name, "mode", "tun").CombinedOutput(); err != nil {
		t.Skipf("no tun device here: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })
	ip(t, "link", "set", name, "up")
	return name
}
