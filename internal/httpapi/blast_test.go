package httpapi

import (
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/blast"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeBlast struct {
	rep        blast.Report
	err        error
	candidates []string
}

func (f *fakeBlast) Preview(candidate []byte) (blast.Report, error) {
	f.candidates = append(f.candidates, string(candidate))
	return f.rep, f.err
}

func sampleBlast() blast.Report {
	return blast.Report{Mode: "inject", Announces: true, Changes: true,
		Add:  []blast.Route{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), From: "transit-a", To: "transit-b"}},
		Move: []blast.Route{}, Withdraw: []blast.Route{}, Providers: []blast.Shift{}, Warnings: []blast.Warning{{Code: blast.WarnCap, Message: "cap"}}}
}

// blastUI is the editor server whose editor classifies thresholds and
// allowlist as online keys and probe.interval as online but harmless, the
// way the controller's classify does.
func blastUI(t *testing.T) (*uiEnv, *fakeBlast) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(editorYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	running, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	diff := func(a, b *config.Config) (restart, online []string) {
		if !reflect.DeepEqual(a.Thresholds, b.Thresholds) {
			online = append(online, "thresholds")
		}
		if a.HoldTime != b.HoldTime {
			online = append(online, "probe.interval")
		}
		return nil, online
	}
	ed, err := configedit.New(path, running, config.Parse, diff)
	if err != nil {
		t.Fatal(err)
	}
	e := newUIWith(t, func(o *Options) { o.ConfigEditor = ed })
	e.path = path
	fb := &fakeBlast{rep: sampleBlast()}
	e.srv.SetBlast(fb)
	return e, fb
}

const (
	widerThresholds = "thresholds: {min_loss_delta_pct: 2, min_rtt_delta_ms: 20}\n"
	otherHold       = "hold_time: 7m\n"
)

func onDisk(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestBlastEndpoint(t *testing.T) {
	e := newUI(t)
	rec, got := e.do(t, "GET", "/api/blast", plugin.RoleOperator, nil)
	if rec.Code != http.StatusOK || got["available"] != false || got["report"] != nil {
		t.Fatalf("without a source: %d %s", rec.Code, rec.Body)
	}

	e, fb := blastUI(t)
	if rec, _ = e.do(t, "GET", "/api/blast", plugin.RoleViewer, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("a viewer previewed: %d", rec.Code)
	}
	rec, got = e.do(t, "GET", "/api/blast", plugin.RoleOperator, nil)
	rep, _ := got["report"].(map[string]any)
	if rec.Code != http.StatusOK || got["available"] != true || rep["announces"] != true || len(rep["add"].([]any)) != 1 {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	if len(fb.candidates) != 1 || fb.candidates[0] != "" {
		t.Fatalf("GET previewed %q, want the running config (no candidate)", fb.candidates)
	}

	fb.err = blast.ErrNoRound
	rec, got = e.do(t, "GET", "/api/blast", plugin.RoleOperator, nil)
	if rec.Code != http.StatusConflict || got["code"] != "no_round" {
		t.Fatalf("no round: %d %s", rec.Code, rec.Body)
	}
}

func TestConfigSaveNeedsPreviewForAnnouncingChange(t *testing.T) {
	e, fb := blastUI(t)
	admin := plugin.RoleAdmin
	base := configedit.Hash([]byte(editorYAML))
	yaml := editorYAML + widerThresholds

	// No token: refused, and the file is as it was.
	rec, got := e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": base})
	if rec.Code != http.StatusPreconditionRequired || got["code"] != "preview_required" {
		t.Fatalf("no token: %d %s", rec.Code, rec.Body)
	}
	// dry_run=false without a token is the same.
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": base, "dry_run": false})
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("dry_run=false without token: %d %s", rec.Code, rec.Body)
	}
	if onDisk(t, e.path) != editorYAML {
		t.Fatal("a refused save wrote the file")
	}

	// A dry run answers with the preview and a token, and writes nothing.
	rec, got = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": base, "dry_run": true})
	token, _ := got["preview_token"].(string)
	rep, _ := got["blast"].(map[string]any)
	if rec.Code != http.StatusOK || got["dry_run"] != true || got["required"] != true || token == "" || len(rep["add"].([]any)) != 1 {
		t.Fatalf("dry run: %d %s", rec.Code, rec.Body)
	}
	if len(fb.candidates) != 1 || fb.candidates[0] != yaml {
		t.Fatalf("previewed %q, want the candidate", fb.candidates)
	}
	if onDisk(t, e.path) != editorYAML {
		t.Fatal("a dry run wrote the file")
	}

	// A token for another candidate, or another revision, does not open it.
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml + "\n", "base": base, "dry_run": false, "preview_token": token})
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("token of another candidate: %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": strings.Repeat("0", 64), "dry_run": false, "preview_token": token})
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("token of another revision: %d %s", rec.Code, rec.Body)
	}

	// The token from the same revision saves it.
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": base, "dry_run": false, "preview_token": token})
	if rec.Code != http.StatusOK {
		t.Fatalf("with token: %d %s", rec.Code, rec.Body)
	}
	if onDisk(t, e.path) != yaml {
		t.Fatal("the confirmed save did not write the file")
	}
}

func TestConfigSavePreviewTokenExpires(t *testing.T) {
	e, _ := blastUI(t)
	admin := plugin.RoleAdmin
	base := configedit.Hash([]byte(editorYAML))
	yaml := editorYAML + widerThresholds
	clock := time.Now()
	e.srv.blastNow = func() time.Time { return clock }

	_, got := e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": base, "dry_run": true})
	token, _ := got["preview_token"].(string)
	clock = clock.Add(previewTokenTTL + time.Second)
	rec, got := e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": base, "dry_run": false, "preview_token": token})
	if rec.Code != http.StatusPreconditionRequired || got["code"] != "preview_required" {
		t.Fatalf("expired token: %d %s", rec.Code, rec.Body)
	}
	if onDisk(t, e.path) != editorYAML {
		t.Fatal("an expired token saved the file")
	}

	// The stamp is signed: an expired token re-stamped to now (inside the
	// window) does not open the save; a future stamp is refused on time.
	_, sig, _ := strings.Cut(token, ".")
	for _, at := range []time.Time{clock, clock.Add(time.Minute)} {
		forged := strconv.FormatInt(at.Unix(), 10) + "." + sig
		if rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": base, "dry_run": false, "preview_token": forged}); rec.Code != http.StatusPreconditionRequired {
			t.Fatalf("forged stamp %v: %d %s", at, rec.Code, rec.Body)
		}
	}

	// A fresh preview at the new time opens it.
	_, got = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": base, "dry_run": true})
	token, _ = got["preview_token"].(string)
	if rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": base, "dry_run": false, "preview_token": token}); rec.Code != http.StatusOK {
		t.Fatalf("fresh token: %d %s", rec.Code, rec.Body)
	}
}

func TestConfigSaveSkipsPreviewWhenNothingAnnounced(t *testing.T) {
	e, _ := blastUI(t)
	admin := plugin.RoleAdmin
	base := configedit.Hash([]byte(editorYAML))
	yaml := editorYAML + otherHold

	rec, got := e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": base, "dry_run": true})
	if rec.Code != http.StatusOK || got["required"] != false || got["preview_token"] != nil {
		t.Fatalf("dry run of a harmless change: %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yaml, "base": base})
	if rec.Code != http.StatusOK || onDisk(t, e.path) != yaml {
		t.Fatalf("harmless change without a token: %d %s", rec.Code, rec.Body)
	}
}

func TestConfigSaveWithoutPreviewSource(t *testing.T) {
	e := newUI(t)
	base := configedit.Hash([]byte(editorYAML))
	rec, _ := e.do(t, "PUT", "/api/config", plugin.RoleAdmin, map[string]any{"yaml": editorYAML + "hold_time: 7m\n", "base": base, "dry_run": true})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("dry run without a source: %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.do(t, "PUT", "/api/config", plugin.RoleAdmin, map[string]any{"yaml": editorYAML + "hold_time: 7m\n", "base": base})
	if rec.Code != http.StatusOK {
		t.Fatalf("save without a source: %d %s", rec.Code, rec.Body)
	}
}

func TestConfigDryRunErrors(t *testing.T) {
	e, fb := blastUI(t)
	admin := plugin.RoleAdmin
	base := configedit.Hash([]byte(editorYAML))
	rec, got := e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": "mode: observe\n", "base": base, "dry_run": true})
	if rec.Code != http.StatusUnprocessableEntity || got["result"] == nil {
		t.Fatalf("invalid candidate: %d %s", rec.Code, rec.Body)
	}
	if len(fb.candidates) != 0 {
		t.Fatalf("an invalid candidate was previewed: %q", fb.candidates)
	}
	fb.err = blast.ErrNoRound
	rec, got = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": editorYAML + widerThresholds, "base": base, "dry_run": true})
	if rec.Code != http.StatusConflict || got["code"] != "no_round" {
		t.Fatalf("no round: %d %s", rec.Code, rec.Body)
	}
	// Only an admin may use the dry run, like the save.
	rec, _ = e.do(t, "PUT", "/api/config", plugin.RoleOperator, map[string]any{"yaml": editorYAML + widerThresholds, "base": base, "dry_run": true})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator dry run: %d", rec.Code)
	}
}
