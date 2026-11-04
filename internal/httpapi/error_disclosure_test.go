package httpapi

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/preflight"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const leakyDetail = "open /var/lib/packeteer/state.db: SQLITE_IOERR secret-path"

type failingReports struct{ fakeReports }

func (*failingReports) Report(context.Context, history.Query) (history.Report, error) {
	return history.Report{}, errors.New(leakyDetail)
}

type failingPreflight struct{ fakePreflight }

func (failingPreflight) Confirm(context.Context, string, string) (preflight.Report, error) {
	return preflight.Report{}, errors.New(leakyDetail)
}

func (failingPreflight) Gate(context.Context, []byte) error { return errors.New(leakyDetail) }

func noDetail(t *testing.T, what string, code, want int, body string) {
	t.Helper()
	if code != want {
		t.Fatalf("%s: status %d, want %d: %s", what, code, want, body)
	}
	if strings.Contains(body, "secret-path") || strings.Contains(body, "SQLITE") || strings.Contains(body, "/var/lib") {
		t.Fatalf("%s returned internal detail: %s", what, body)
	}
	if !strings.Contains(body, `"error"`) {
		t.Fatalf("%s has no error message: %s", what, body)
	}
}

// A store, file, or path error is logged and never sent to the caller.
func TestServerErrorsAreGeneric(t *testing.T) {
	t.Run("report", func(t *testing.T) {
		ts := reportServer(t, &failingReports{}, "", "")
		code, _, body := do(t, http.MethodGet, ts.URL+"/api/reports/summary", "", "")
		noDetail(t, "report", code, http.StatusInternalServerError, string(body))
	})

	t.Run("blast preview", func(t *testing.T) {
		e, fb := blastUI(t)
		fb.err = errors.New(leakyDetail)
		rec, _ := e.do(t, "GET", "/api/blast", plugin.RoleOperator, nil)
		noDetail(t, "blast", rec.Code, http.StatusInternalServerError, rec.Body.String())
	})

	t.Run("preflight confirm and gate", func(t *testing.T) {
		f := goodFacts()
		e := newPreflightUI(t, &f)
		e.srv.SetPreflight(failingPreflight{fakePreflight{e.srv.preflightControl().(fakePreflight).Runner}})
		rec, _ := e.do(t, "POST", "/api/preflight/confirm", plugin.RoleAdmin, map[string]string{"id": "import_filter"})
		noDetail(t, "confirm", rec.Code, http.StatusInternalServerError, rec.Body.String())

		_, got := e.do(t, "GET", "/api/config", plugin.RoleAdmin, nil)
		save := map[string]any{"yaml": editorInjectYAML, "base": got["sha256"], "confirm_inject": true}
		rec, _ = e.do(t, "PUT", "/api/config", plugin.RoleAdmin, save)
		noDetail(t, "gate", rec.Code, http.StatusInternalServerError, rec.Body.String())
	})

	t.Run("config write", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores file permissions")
		}
		e := newUI(t)
		_, got := e.do(t, "GET", "/api/config", plugin.RoleAdmin, nil)
		dir := filepath.Dir(e.path)
		if err := os.Chmod(e.path, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		rec, _ := e.do(t, "PUT", "/api/config", plugin.RoleAdmin, map[string]any{"yaml": strings.Replace(editorYAML, "192.0.2.10", "192.0.2.20", 1), "base": got["sha256"]})
		noDetail(t, "write", rec.Code, http.StatusInternalServerError, rec.Body.String())
		if strings.Contains(rec.Body.String(), dir) {
			t.Fatalf("the config path leaked: %s", rec.Body)
		}
	})

	t.Run("setup skip and send now", func(t *testing.T) {
		fr := &fakeFirstRun{pending: true, err: errors.New(leakyDetail)}
		e := newUIWith(t, func(o *Options) { o.FirstRun = fr })
		rec, _ := e.do(t, "POST", "/api/setup/skip", plugin.RoleAdmin, nil)
		noDetail(t, "setup skip", rec.Code, http.StatusInternalServerError, rec.Body.String())

		e.subs.fail = errors.New(leakyDetail)
		rec, _ = e.do(t, "POST", "/api/subscriptions/weekly/send", plugin.RoleOperator, nil)
		noDetail(t, "send now", rec.Code, http.StatusBadGateway, rec.Body.String())
	})
}
