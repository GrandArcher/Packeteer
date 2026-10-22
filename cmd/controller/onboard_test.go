package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const onboardConfig = `mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
bgp:
  neighbors:
    - address: 192.0.2.254
`

func writeOnboardConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunSnippetPrintsTheRouterConfig(t *testing.T) {
	path := writeOnboardConfig(t, onboardConfig)
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-config", path, "-snippet", "frr"}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
	for _, want := range []string{"bgp community-list standard packeteer permit 64512:666", "neighbor 192.0.2.10 remote-as 64512", "route-map ebgp-out deny 10"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if code := run(context.Background(), []string{"-config", path, "-snippet", "cumulus"}, noEnv, &out, &errOut); code != 1 || out.Len() != 0 {
		t.Fatalf("unknown vendor: code %d, stdout %q", code, out.String())
	}
	if !strings.Contains(errOut.String(), "unknown vendor") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

// scriptedIP answers ip commands for one provider. changes records the
// commands that modify the host.
type scriptedIP struct {
	applied bool
	changes []string
	failAdd bool
}

func (s *scriptedIP) exec(_ context.Context, args ...string) (string, error) {
	line := strings.Join(args, " ")
	switch {
	case line == "rule show":
		if s.applied {
			return "2001:\tfrom 192.0.2.11 lookup 1001\n", nil
		}
		return "0:\tfrom all lookup local\n", nil
	case line == "route show table 1001":
		return "default via 192.0.2.1 dev eth0\n", nil
	case strings.HasPrefix(line, "route get"):
		return "203.0.113.254 from 192.0.2.11 via 192.0.2.1 dev eth0 table 1001\n", nil
	case strings.HasPrefix(line, "-6 rule show"):
		return "", errors.New("ip: IPv6 is not supported")
	case strings.Contains(line, " add ") || strings.Contains(line, " replace "):
		if s.failAdd {
			return "", errors.New("RTNETLINK answers: Operation not permitted")
		}
		s.changes = append(s.changes, line)
		s.applied = true
	}
	return "", nil
}

func TestRunPBRApplyShowsTheDiffAndChangesNothingWithoutYes(t *testing.T) {
	path := writeOnboardConfig(t, onboardConfig)
	ip := &scriptedIP{}
	old := hostIP
	hostIP = ip.exec
	t.Cleanup(func() { hostIP = old })
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-config", path, "-pbr", "linux", "-apply"}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "+ ip rule add from 192.0.2.11 lookup 1001 priority 2001") || !strings.Contains(out.String(), "Nothing was changed. Add -yes") {
		t.Errorf("stdout:\n%s", out.String())
	}
	if len(ip.changes) != 0 {
		t.Fatalf("changed the host without -yes: %v", ip.changes)
	}
}

func TestRunPBRApplyYesAppliesThenVerifies(t *testing.T) {
	path := writeOnboardConfig(t, onboardConfig)
	ip := &scriptedIP{}
	old := hostIP
	hostIP = ip.exec
	t.Cleanup(func() { hostIP = old })
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-config", path, "-pbr", "linux", "-apply", "-yes"}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
	if len(ip.changes) != 2 || !strings.Contains(out.String(), "Applied 2 changes.") || !strings.Contains(out.String(), "leave through its next hop") {
		t.Fatalf("changes %v, stdout:\n%s", ip.changes, out.String())
	}
	// Run again: nothing to do, and the check still runs.
	out.Reset()
	if code := run(context.Background(), []string{"-config", path, "-pbr", "linux", "-apply"}, noEnv, &out, &errOut); code != 0 || !strings.Contains(out.String(), "already has the policy routing") {
		t.Fatalf("second run: code %d, stdout:\n%s", code, out.String())
	}
}

func TestRunPBRApplyReportsFailuresAndMisuse(t *testing.T) {
	path := writeOnboardConfig(t, onboardConfig)
	ip := &scriptedIP{failAdd: true}
	old := hostIP
	hostIP = ip.exec
	t.Cleanup(func() { hostIP = old })
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-config", path, "-pbr", "linux", "-apply", "-yes"}, noEnv, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "Operation not permitted") {
		t.Fatalf("failed add: code %d, stderr %q", code, errOut.String())
	}
	for _, args := range [][]string{
		{"-config", path, "-apply"},
		{"-config", path, "-pbr", "frr", "-apply"},
		{"-config", path, "-pbr", "linux", "-yes"},
	} {
		errOut.Reset()
		if code := run(context.Background(), args, noEnv, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "-apply") {
			t.Errorf("%v: code %d, stderr %q", args, code, errOut.String())
		}
	}
	// A route that leaves the wrong way fails the check.
	hostIP = func(ctx context.Context, args ...string) (string, error) {
		if args[0] == "route" && args[1] == "get" {
			return "203.0.113.254 from 192.0.2.11 via 192.0.2.99 dev eth0\n", nil
		}
		return (&scriptedIP{applied: true}).exec(ctx, args...)
	}
	errOut.Reset()
	if code := run(context.Background(), []string{"-config", path, "-pbr", "linux", "-apply"}, noEnv, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "not via 192.0.2.1") {
		t.Fatalf("wrong way: code %d, stderr %q", code, errOut.String())
	}
}
