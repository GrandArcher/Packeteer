package httpapi

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/registry"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// pageRPKI answers for two documentation prefixes: one invalid because the
// ROA is too short, one with no ROA.
type pageRPKI struct{}

func (pageRPKI) Enabled() bool { return true }

func (pageRPKI) Lookup(p netip.Prefix, _ uint32) plugin.RPKIAnswer {
	if p.Addr().As4()[2] == 100 {
		return plugin.RPKIAnswer{State: plugin.RPKIInvalid}
	}
	return plugin.RPKIAnswer{State: plugin.RPKINotFound}
}

func (pageRPKI) Covering(netip.Prefix) []plugin.RPKIVRP {
	return []plugin.RPKIVRP{{Prefix: netip.MustParsePrefix("198.51.100.0/23"), MaxLen: 23, ASN: 64496}}
}

type pageInfoChecker struct{ plugin.Base }

func (pageInfoChecker) Check(context.Context, plugin.RegistryFacts) ([]plugin.RegistryFinding, error) {
	return []plugin.RegistryFinding{{Kind: "pdb_contact_old", Severity: plugin.RegistryInfo, Registry: "peeringdb", Subject: "AS64496 contacts", Message: "contact not updated for 3 years"}}, nil
}
func (pageInfoChecker) Push(context.Context, plugin.RegistryChange) error { return nil }

type pageDownChecker struct{ plugin.Base }

func (pageDownChecker) Check(context.Context, plugin.RegistryFacts) ([]plugin.RegistryFinding, error) {
	return nil, errors.New("rest.db.example.net unreachable")
}
func (pageDownChecker) Push(context.Context, plugin.RegistryChange) error { return nil }

// #289: the Registry page renders a real scan report and drives the push
// control in Node. It is skipped without Node locally and required in CI.
func TestRegistryPageRendering(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the registry page test")
		}
		t.Skip("node not installed")
	}
	svc := registry.New(registry.Config{ASNs: []uint32{64496}, PushEnabled: true}, registry.Deps{
		Observe: func() registry.Observed {
			return registry.Observed{Ready: true, Announced: map[netip.Prefix]uint32{
				netip.MustParsePrefix("198.51.100.0/24"): 64496,
				netip.MustParsePrefix("203.0.113.0/24"):  64496,
			}}
		},
		RPKI: pageRPKI{},
		Checkers: []registry.Checker{
			{Name: "peeringdb", Type: "peeringdb", Plugin: &pdbStub{}},
			{Name: "peeringdb-contacts", Type: "contacts", Plugin: pageInfoChecker{}},
			{Name: "ripe", Type: "ripe", Plugin: pageDownChecker{}},
		},
	})
	svc.Scan(context.Background())
	e := newRBAC(t, nil)
	e.srv.SetRegistry(svc)
	rec := e.do("GET", "/api/registry", e.tokens[plugin.RoleViewer], "")
	if rec.Code != 200 {
		t.Fatalf("GET /api/registry = %d %s", rec.Code, rec.Body)
	}
	file := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(file, rec.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "registry_page_test.js", file).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("registry page: %v\n%s", err, out)
	}
}

// #289: the page is served and every page's side nav links to it.
func TestRegistryPageServedAndLinked(t *testing.T) {
	e := newRBAC(t, nil)
	rec := e.do("GET", "/registry.html", e.tokens[plugin.RoleViewer], "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `<script src="/registry.js"></script>`) {
		t.Fatalf("registry.html = %d", rec.Code)
	}
	if rec := e.do("GET", "/registry.js", e.tokens[plugin.RoleViewer], ""); rec.Code != 200 {
		t.Fatalf("registry.js = %d", rec.Code)
	}
	pages, err := filepath.Glob("web/*.html")
	if err != nil || len(pages) < 10 {
		t.Fatalf("pages = %v, %v", pages, err)
	}
	for _, p := range pages {
		if filepath.Base(p) == "signin.html" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `<a href="/registry.html" data-page="registry">Registry</a>`) {
			t.Errorf("%s has no Registry link in the side nav", p)
		}
	}
}
