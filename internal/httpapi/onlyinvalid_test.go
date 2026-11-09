package httpapi

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/onlyinvalid"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// oneRouteRIB learns 198.51.100.0/24 from AS64500 through two transits.
type oneRouteRIB struct{ paths []rib.Route }

func (oneRouteRIB) Ready() bool { return true }
func (o oneRouteRIB) Find(keep func(rib.Route) bool, _ func(a, b rib.Route) bool, _ int) ([]rib.Route, int) {
	if keep(o.paths[0]) {
		return o.paths[:1], 1
	}
	return nil, 0
}
func (o oneRouteRIB) Paths(p netip.Prefix) []rib.Route {
	if p == o.paths[0].Prefix {
		return slices.Clone(o.paths)
	}
	return nil
}
func (o oneRouteRIB) Covering(p netip.Prefix) (rib.Route, bool) {
	if netpfx.CoveredBy([]netip.Prefix{o.paths[0].Prefix}, p) {
		return o.paths[0], true
	}
	return rib.Route{}, false
}

type vrpView struct{ *rpki.VRPs }

func (v vrpView) Lookup(p netip.Prefix, origin uint32) plugin.RPKIAnswer {
	return plugin.RPKIAnswer{State: v.Validate(p, origin), Source: "routinator", Updated: time.Now()}
}
func (vrpView) Updated() time.Time { return time.Now() }

func onlyInvalidEnv(t *testing.T) (*rbacEnv, string) {
	t.Helper()
	e := newRBAC(t, nil)
	p := netip.MustParsePrefix("198.51.100.0/24")
	long := time.Now().Add(-90 * 24 * time.Hour)
	r := oneRouteRIB{paths: []rib.Route{
		{Prefix: p, Provider: "transit-a", ASPath: []uint32{64496, 64500}, Age: long},
		{Prefix: p, Provider: "transit-b", ASPath: []uint32{64497, 64500}, Age: long},
	}}
	vrps := rpki.NewVRPs()
	vrps.Apply([]rpki.Change{{Prefix: netip.MustParsePrefix("198.51.100.0/22"), MaxLen: 22, ASN: 64500}})
	irr := func(netip.Prefix, uint32, string) plugin.IRRAnswer {
		return plugin.IRRAnswer{State: plugin.IRRRegistered, Source: "radb-file", Database: "RADB", Origins: []uint32{64500}}
	}
	det := onlyinvalid.NewDetector(onlyinvalid.Deps{RIB: r, RPKI: vrpView{vrps}, IRR: irr}, 0)
	det.Scan(context.Background())
	path := filepath.Join(t.TempDir(), "slurm.json")
	ex := onlyinvalid.NewExceptions(onlyinvalid.SLURMConfig{Path: path, Prefixes: []netip.Prefix{p}}, det, auth.NewAuditor(e.store, nil, nil))
	e.srv.SetOnlyInvalid(&onlyinvalid.Service{Detector: det, Exceptions: ex})
	return e, path
}

// #401: with nothing configured the endpoints report off and change
// nothing.
func TestOnlyInvalidOff(t *testing.T) {
	e := newRBAC(t, nil)
	var body struct {
		Enabled bool `json:"enabled"`
		Cases   []any
		SLURM   struct {
			Enabled bool `json:"enabled"`
		} `json:"slurm"`
	}
	rec := e.do("GET", "/api/rpki/only-invalid", e.tokens[plugin.RoleViewer], "")
	jsonOf(t, rec.Body, &body)
	if rec.Code != http.StatusOK || body.Enabled || body.SLURM.Enabled || body.Cases == nil || len(body.Cases) != 0 {
		t.Fatalf("off: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/rpki/only-invalid/propose", e.tokens[plugin.RoleAdmin], `{"prefix":"198.51.100.0/24"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("propose off: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("GET", "/api/rpki/slurm", e.tokens[plugin.RoleViewer], ""); rec.Code != http.StatusNotFound {
		t.Fatalf("slurm off: %d", rec.Code)
	}
}

// #401: a viewer sees the case and its evidence, an operator proposes
// and nothing is written, only an admin with the digest shown writes the
// file, and every step is in the audit log.
func TestOnlyInvalidProposeApprove(t *testing.T) {
	e, path := onlyInvalidEnv(t)
	var list struct {
		Cases []struct {
			Prefix  string `json:"prefix"`
			Class   string `json:"class"`
			Signals []struct {
				Name string `json:"name"`
			} `json:"signals"`
		} `json:"cases"`
		SLURM struct {
			Enabled  bool     `json:"enabled"`
			Writable bool     `json:"writable"`
			Prefixes []string `json:"prefixes"`
		} `json:"slurm"`
	}
	jsonOf(t, e.do("GET", "/api/rpki/only-invalid?prefix=198.51.100.0/24", e.tokens[plugin.RoleViewer], "").Body, &list)
	if len(list.Cases) != 1 || list.Cases[0].Class != onlyinvalid.ClassStaleROA || len(list.Cases[0].Signals) == 0 || !list.SLURM.Enabled || !list.SLURM.Writable {
		t.Fatalf("list = %+v", list)
	}
	jsonOf(t, e.do("GET", "/api/rpki/only-invalid?prefix=192.0.2.0/24", e.tokens[plugin.RoleViewer], "").Body, &list)
	if len(list.Cases) != 0 {
		t.Fatalf("prefix filter: %+v", list.Cases)
	}

	if rec := e.do("POST", "/api/rpki/only-invalid/propose", e.tokens[plugin.RoleViewer], `{"prefix":"198.51.100.0/24"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer proposed: %d", rec.Code)
	}
	rec := e.do("POST", "/api/rpki/only-invalid/propose", e.tokens[plugin.RoleOperator], `{"prefix":"198.51.100.0/24"}`)
	var prop struct {
		ID      string `json:"id"`
		Digest  string `json:"digest"`
		Kind    string `json:"kind"`
		Entries any    `json:"entries"`
		After   string `json:"state_after"`
	}
	jsonOf(t, rec.Body, &prop)
	if rec.Code != http.StatusOK || prop.Kind != onlyinvalid.KindAssertion || prop.After != "valid" || prop.Digest == "" {
		t.Fatalf("propose: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a proposal wrote the file")
	}
	approve := `{"id":"` + prop.ID + `","digest":"` + prop.Digest + `"}`
	if rec := e.do("POST", "/api/rpki/exceptions", e.tokens[plugin.RoleOperator], approve); rec.Code != http.StatusForbidden {
		t.Fatalf("operator approved: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/rpki/exceptions", e.tokens[plugin.RoleAdmin], `{"id":"`+prop.ID+`","digest":"bad"}`); rec.Code != http.StatusConflict {
		t.Fatalf("wrong digest: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/rpki/exceptions", e.tokens[plugin.RoleAdmin], approve); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	file := e.do("GET", "/api/rpki/slurm", e.tokens[plugin.RoleViewer], "")
	onDisk, _ := os.ReadFile(path)
	if file.Code != http.StatusOK || file.Body.String() != string(onDisk) || !strings.Contains(string(onDisk), `"prefix": "198.51.100.0/24"`) {
		t.Fatalf("export %d:\n%s\nfile:\n%s", file.Code, file.Body, onDisk)
	}
	var ex struct {
		SLURM struct {
			Exceptions []struct {
				ID      string `json:"id"`
				AuditID string `json:"audit_id"`
			} `json:"exceptions"`
			Held []string `json:"held"`
		} `json:"slurm"`
	}
	jsonOf(t, e.do("GET", "/api/rpki/only-invalid", e.tokens[plugin.RoleViewer], "").Body, &ex)
	if len(ex.SLURM.Held) != 1 || ex.SLURM.Held[0] != "198.51.100.0/24" {
		t.Fatalf("held = %v", ex.SLURM.Held)
	}
	if len(ex.SLURM.Exceptions) != 1 || ex.SLURM.Exceptions[0].AuditID != prop.ID {
		t.Fatalf("exceptions = %+v", ex)
	}
	if rec := e.do("DELETE", "/api/rpki/exceptions/"+ex.SLURM.Exceptions[0].ID, e.tokens[plugin.RoleAdmin], ""); rec.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("DELETE", "/api/rpki/exceptions/"+ex.SLURM.Exceptions[0].ID, e.tokens[plugin.RoleAdmin], ""); rec.Code != http.StatusNotFound {
		t.Fatalf("remove twice: %d", rec.Code)
	}

	recs, err := e.store.Audit(context.Background(), plugin.AuditQuery{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, r := range recs {
		seen[r.Action] = r.Detail
	}
	for _, a := range []string{onlyinvalid.ActionPropose, onlyinvalid.ActionApprove, onlyinvalid.ActionWrite, onlyinvalid.ActionRemove} {
		if seen[a] == "" {
			t.Errorf("audit has no %s record: %v", a, seen)
		}
	}
	if !strings.Contains(seen[onlyinvalid.ActionApprove], "class=stale_roa") || !strings.Contains(seen[onlyinvalid.ActionPropose], "irr_route +2") {
		t.Errorf("audit records lack the evidence: %v", seen)
	}
	if seen["POST /api/rpki/exceptions"] == "" {
		t.Errorf("the approval request is not audited: %v", seen)
	}
}
