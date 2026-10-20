package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeFirstRun struct {
	pending bool
	calls   int
	err     error
}

func (f *fakeFirstRun) Pending() bool { return f.pending }
func (f *fakeFirstRun) Complete() error {
	f.calls++
	f.pending = false
	return f.err
}

// While setup is pending an admin is told so in /api/me; a lower role is
// not, and neither is an admin once setup is skipped.
func TestSetupPendingInMe(t *testing.T) {
	fr := &fakeFirstRun{pending: true}
	e := newUIWith(t, func(o *Options) { o.FirstRun = fr })
	_, got := e.do(t, "GET", "/api/me", plugin.RoleAdmin, nil)
	if got["setup_pending"] != true {
		t.Fatalf("admin while pending: %v", got)
	}
	for _, r := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator} {
		if _, got := e.do(t, "GET", "/api/me", r, nil); got["setup_pending"] != nil {
			t.Fatalf("%s sees setup_pending: %v", r, got)
		}
	}
	fr.pending = false
	if _, got := e.do(t, "GET", "/api/me", plugin.RoleAdmin, nil); got["setup_pending"] != nil {
		t.Fatalf("admin after setup: %v", got)
	}
}

// Skip is admin only, ends setup, and leaves the saved state to FirstRun.
func TestSetupSkip(t *testing.T) {
	fr := &fakeFirstRun{pending: true}
	e := newUIWith(t, func(o *Options) { o.FirstRun = fr })
	for _, r := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator} {
		if rec, _ := e.do(t, "POST", "/api/setup/skip", r, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("%s skip: %d %s", r, rec.Code, rec.Body)
		}
	}
	if fr.calls != 0 || !fr.pending {
		t.Fatalf("a refused skip changed the state: %+v", fr)
	}
	rec, got := e.do(t, "POST", "/api/setup/skip", plugin.RoleAdmin, nil)
	if rec.Code != http.StatusOK || got["pending"] != false || fr.calls != 1 || fr.pending {
		t.Fatalf("admin skip: %d %s %+v", rec.Code, rec.Body, fr)
	}
	if _, got := e.do(t, "GET", "/api/me", plugin.RoleAdmin, nil); got["setup_pending"] != nil {
		t.Fatalf("still pending after skip: %v", got)
	}
}

// A skip whose state cannot be saved says so, while this run stops
// asking.
func TestSetupSkipSaveFails(t *testing.T) {
	fr := &fakeFirstRun{pending: true, err: errors.New("read-only volume")}
	e := newUIWith(t, func(o *Options) { o.FirstRun = fr })
	rec, got := e.do(t, "POST", "/api/setup/skip", plugin.RoleAdmin, nil)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(got["error"].(string), "read-only volume") || fr.pending {
		t.Fatalf("skip: %d %s %+v", rec.Code, rec.Body, fr)
	}
}

// Without first-run state (the editor is explicit, or off) there is
// nothing to skip. With no sign-in at all the route is refused too.
func TestSetupSkipNotAvailable(t *testing.T) {
	e := newUI(t)
	if rec, _ := e.do(t, "POST", "/api/setup/skip", plugin.RoleAdmin, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("no first-run state: %d %s", rec.Code, rec.Body)
	}
	fr := &fakeFirstRun{pending: true}
	srv, err := New(Options{FirstRun: fr, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/api/setup/skip", nil))
	if rec.Code != http.StatusNotFound || fr.calls != 0 {
		t.Fatalf("auth off: %d %s calls=%d", rec.Code, rec.Body, fr.calls)
	}
}

// TestFirstRunPage runs the dashboard redirect and the Skip button in
// Node. Like the settings form test, it is skipped without Node locally
// and required in CI.
func TestFirstRunPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the first-run page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "first_run_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("first-run page: %v\n%s", err, out)
	}
}
