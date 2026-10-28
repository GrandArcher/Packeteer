package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/replay"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeWhatIf struct {
	res  replay.Result
	err  error
	reqs []string
}

func (f *fakeWhatIf) Replay(_ context.Context, candidate []byte, from, to string) (replay.Result, error) {
	f.reqs = append(f.reqs, fmt.Sprintf("%s|%s|%s", candidate, from, to))
	return f.res, f.err
}

func TestWhatIfEndpoint(t *testing.T) {
	e := newUI(t)
	body := map[string]any{"yaml": "mode: observe\n", "from": "6h"}
	if rec, _ := e.do(t, "POST", "/api/whatif", plugin.RoleAdmin, body); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "round_retention") {
		t.Fatalf("without a source: %d %s", rec.Code, rec.Body)
	}

	f := &fakeWhatIf{res: replay.Result{Rounds: 3, Sides: []replay.Report{{Name: "running config"}, {Name: "candidate config"}},
		Diff: []replay.PrefixDiff{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Base: []string{"transit-b"}}}}}
	e.srv.SetWhatIf(f)
	for _, role := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator} {
		if rec, _ := e.do(t, "POST", "/api/whatif", role, body); rec.Code != http.StatusForbidden {
			t.Fatalf("%s replayed: %d", role, rec.Code)
		}
	}
	rec, got := e.do(t, "POST", "/api/whatif", plugin.RoleAdmin, body)
	diff, _ := got["diff"].([]any)
	if rec.Code != http.StatusOK || got["rounds"] != float64(3) || len(diff) != 1 {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body)
	}
	if len(f.reqs) != 1 || f.reqs[0] != "mode: observe\n|6h|" {
		t.Fatalf("request passed on: %q", f.reqs)
	}
	if rec, _ := e.do(t, "POST", "/api/whatif", plugin.RoleAdmin, map[string]any{"yaml": "", "nope": 1}); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}

	for _, c := range []struct {
		err  error
		code int
		name string
	}{
		{fmt.Errorf("%w: from must be before to", ErrWhatIfInput), http.StatusUnprocessableEntity, "invalid"},
		{ErrWhatIfBusy, http.StatusTooManyRequests, "busy"},
		{fmt.Errorf("window: %w", replay.ErrNoRounds), http.StatusNotFound, "no_rounds"},
	} {
		f.err = c.err
		rec, got := e.do(t, "POST", "/api/whatif", plugin.RoleAdmin, body)
		if rec.Code != c.code || got["code"] != c.name {
			t.Errorf("%v: %d %s", c.err, rec.Code, rec.Body)
		}
	}
	f.err = fmt.Errorf("replay: %w", context.Canceled)
	if rec, _ := e.do(t, "POST", "/api/whatif", plugin.RoleAdmin, body); rec.Code == http.StatusInternalServerError {
		t.Fatalf("a client disconnect is a server error: %d %s", rec.Code, rec.Body)
	}
	f.err = errors.New("disk")
	if rec, _ := e.do(t, "POST", "/api/whatif", plugin.RoleAdmin, body); rec.Code != http.StatusInternalServerError {
		t.Fatalf("other error: %d", rec.Code)
	}
}
