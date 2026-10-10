package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"v0.6.0", "0.5.0", 1, true},
		{"v0.5.0", "0.5.0", 0, true},
		{"v0.4.9", "0.5.0", -1, true},
		{"v0.10.0", "0.9.0", 1, true},
		{"v0.6.0-rc1", "0.6.0", -1, true},
		{"v0.6.0", "0.6.0-rc1", 1, true},
		{"v0.6.0", "dev", 0, false},
		{"v0.6", "0.5.0", 0, false},
	} {
		got, ok := Compare(tc.a, tc.b)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d, %v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
	for _, bad := range []string{"", "../x", "v1.2.3/../../etc", "latest", "v1.2.3 ", "1.2.3-"} {
		if ValidTag(bad) {
			t.Errorf("ValidTag(%q) = true", bad)
		}
	}
}

func TestSignAndChecksum(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("abc  packeteer-linux-amd64\n")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(pub, msg, []byte(sig)); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(pub, append(msg, 'x'), []byte(sig)); err == nil {
		t.Fatal("tampered message verified")
	}
	other, _, _ := GenerateKey()
	if err := VerifySignature(other, msg, []byte(sig)); err == nil {
		t.Fatal("wrong key verified")
	}
	if err := VerifySignature(pub, msg, []byte("not base64!")); err == nil {
		t.Fatal("garbage signature verified")
	}
	sums := []byte(strings.Repeat("a", 64) + "  packeteer-linux-amd64\n" + strings.Repeat("b", 64) + " *packeteer-linux-arm64\n")
	if h, err := checksumFor(sums, "packeteer-linux-arm64"); err != nil || h != strings.Repeat("b", 64) {
		t.Fatalf("checksumFor = %q, %v", h, err)
	}
	if _, err := checksumFor(sums, "packeteer-linux-386"); err == nil {
		t.Fatal("missing entry accepted")
	}
	if _, err := checksumFor([]byte("zz  packeteer-linux-amd64\n"), "packeteer-linux-amd64"); err == nil {
		t.Fatal("short digest accepted")
	}
}

// fakeRelease is a GitHub-like server with one release per entry.
type fakeRelease struct {
	srv  *httptest.Server
	pub  string
	priv string
	// per tag: body of the binary, and mutations.
	bins    map[string]string
	badSig  bool
	badSum  bool
	hits    atomic.Int32
	notes   map[string]string
	missing map[string]bool // tag -> no signature asset
}

const goodScript = "#!/bin/sh\ncase \"$1\" in -version) echo \"packeteer %s\";; -check) exit ${CHECK_EXIT:-0};; esac\n"

func script(version string) string { return fmt.Sprintf(goodScript, version) }

func newFake(t *testing.T, versions ...string) *fakeRelease {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRelease{pub: pub, priv: priv, bins: map[string]string{}, notes: map[string]string{}, missing: map[string]bool{}}
	for _, v := range versions {
		f.bins[v] = script(Normalize(v))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/example/packeteer/releases", func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		var parts []string
		for _, v := range versions {
			assets := []string{
				fmt.Sprintf(`{"name":"packeteer-linux-amd64","browser_download_url":"%s/dl/%s/packeteer-linux-amd64"}`, f.srv.URL, v),
				fmt.Sprintf(`{"name":"packeteer-linux-arm64","browser_download_url":"%s/dl/%s/packeteer-linux-arm64"}`, f.srv.URL, v),
				fmt.Sprintf(`{"name":"SHA256SUMS","browser_download_url":"%s/dl/%s/SHA256SUMS"}`, f.srv.URL, v),
			}
			if !f.missing[v] {
				assets = append(assets, fmt.Sprintf(`{"name":"SHA256SUMS.sig","browser_download_url":"%s/dl/%s/SHA256SUMS.sig"}`, f.srv.URL, v))
			}
			parts = append(parts, fmt.Sprintf(`{"tag_name":%q,"name":%q,"body":%q,"html_url":"https://example.net/r/%s","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z","assets":[%s]}`,
				v, "Packeteer "+v, f.notes[v], v, strings.Join(assets, ",")))
		}
		parts = append(parts, `{"tag_name":"v9.9.9","draft":true,"assets":[]}`, `{"tag_name":"nightly","draft":false,"assets":[]}`)
		fmt.Fprintf(w, "[%s]", strings.Join(parts, ","))
	})
	mux.HandleFunc("GET /dl/{tag}/{name}", func(w http.ResponseWriter, r *http.Request) {
		tag, name := r.PathValue("tag"), r.PathValue("name")
		bin := f.bins[tag]
		sum := sha256.Sum256([]byte(bin))
		hexsum := hex.EncodeToString(sum[:])
		if f.badSum {
			hexsum = strings.Repeat("0", 64)
		}
		sums := fmt.Sprintf("%s  packeteer-linux-amd64\n%s  packeteer-linux-arm64\n", hexsum, hexsum)
		switch name {
		case "packeteer-linux-amd64", "packeteer-linux-arm64":
			io.WriteString(w, bin)
		case "SHA256SUMS":
			io.WriteString(w, sums)
		case "SHA256SUMS.sig":
			sig, _ := Sign(f.priv, []byte(sums))
			if f.badSig {
				sig, _ = Sign(f.priv, []byte("something else"))
			}
			io.WriteString(w, sig)
		default:
			http.NotFound(w, r)
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

type rig struct {
	m       *Manager
	dir     string
	stopped atomic.Int32
	f       *fakeRelease
	ha      *plugin.ElectorStatus
	base    string
}

func newRig(t *testing.T, f *fakeRelease, version string) *rig {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "upgrade")
	r := &rig{dir: dir, f: f, base: filepath.Join(t.TempDir(), "packeteer")}
	if err := os.WriteFile(r.base, []byte(script(version)), 0o755); err != nil {
		t.Fatal(err)
	}
	opt := Options{
		Config:  config.Upgrade{Enabled: true, PublicKey: f.pub, Repo: "example/packeteer", APIURL: f.srv.URL, Dir: dir},
		Version: version, Exe: r.base, Environ: []string{"PATH=" + os.Getenv("PATH")},
		Stop: func() { r.stopped.Add(1) }, StopDelay: time.Millisecond, Log: quiet, Arch: "amd64",
		HA: func() plugin.ElectorStatus {
			if r.ha == nil {
				return plugin.ElectorStatus{}
			}
			return *r.ha
		},
	}
	m, err := New(opt, false)
	if err != nil {
		t.Fatal(err)
	}
	r.m = m
	return r
}

func (r *rig) noHA() { r.m.opt.HA = nil }

func (r *rig) stateExists() bool {
	_, err := os.Stat(filepath.Join(r.dir, "state.json"))
	return err == nil
}

func (r *rig) waitStop(t *testing.T) {
	t.Helper()
	for range 200 {
		if r.stopped.Load() > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("Stop was never called")
}

func TestCheckListsInstallableReleases(t *testing.T) {
	f := newFake(t, "v0.6.0", "v0.5.0")
	f.notes["v0.6.0"] = "<script>alert(1)</script> notes"
	r := newRig(t, f, "0.5.0")
	st, err := r.m.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Releases) != 2 {
		t.Fatalf("drafts and non-version tags must be skipped: %+v", st.Releases)
	}
	if !st.Available || st.Latest.Tag != "v0.6.0" || !st.Latest.Installable || !st.Latest.Newer {
		t.Fatalf("latest = %+v", st.Latest)
	}
	if !st.Releases[1].Current || st.Releases[1].Newer {
		t.Fatalf("running release = %+v", st.Releases[1])
	}
	if st.Releases[0].Notes != "<script>alert(1)</script> notes" {
		t.Fatalf("notes = %q", st.Releases[0].Notes)
	}
	if r.stateExists() || r.stopped.Load() != 0 {
		t.Fatal("a check changed something")
	}
	// A release without the signature asset is listed but not installable.
	f.missing["v0.6.0"] = true
	st, _ = r.m.Check(context.Background())
	if st.Available || st.Releases[0].Installable {
		t.Fatalf("unsigned release is installable: %+v", st.Releases[0])
	}
}

func TestCheckFailureIsReported(t *testing.T) {
	f := newFake(t, "v0.6.0")
	r := newRig(t, f, "0.5.0")
	f.srv.Close()
	st, err := r.m.Check(context.Background())
	if !errors.Is(err, ErrFetch) || st.CheckError == "" {
		t.Fatalf("err = %v, status = %+v", err, st)
	}
}

func TestApplyStagesVerifiesAndSwitches(t *testing.T) {
	f := newFake(t, "v0.6.0", "v0.5.0")
	r := newRig(t, f, "0.5.0")
	r.noHA()
	res, err := r.m.Apply(context.Background(), Request{Tag: "v0.6.0", Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "0.5.0" || res.To != "0.6.0" || !strings.Contains(res.Message, "withdrawn") {
		t.Fatalf("result = %+v", res)
	}
	r.waitStop(t)
	tg, ok := r.m.Pending()
	if !ok || tg.Path != filepath.Join(r.dir, "versions", "0.6.0", "packeteer") {
		t.Fatalf("pending = %+v %v", tg, ok)
	}
	if !strings.Contains(strings.Join(tg.Env, "\n"), LaunchedEnv+"=0.6.0") {
		t.Fatalf("env = %v", tg.Env)
	}
	if fi, err := os.Stat(tg.Path); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("staged binary: %v %v", fi, err)
	}
	st, _ := r.m.store.load()
	if st.Active.Version != "0.6.0" || st.Previous.Path != r.base || st.BaseVersion != "0.5.0" || st.Attempts != 1 || st.Confirmed {
		t.Fatalf("state = %+v", st)
	}
	if got := r.m.Status(); got.Pending != "0.6.0" || got.Rollback == nil || got.Rollback.Version != "0.5.0" {
		t.Fatalf("status = %+v", got)
	}
	// While a switch is pending nothing else may start.
	if _, err := r.m.Apply(context.Background(), Request{Tag: "v0.5.0", Confirm: true}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second apply: %v", err)
	}
}

func TestApplyRefusals(t *testing.T) {
	f := newFake(t, "v0.6.0", "v0.5.0")
	r := newRig(t, f, "0.5.0")
	r.noHA()
	ctx := context.Background()
	for _, tc := range []struct {
		req  Request
		want error
	}{
		{Request{Tag: "v0.6.0"}, ErrNoConfirm},
		{Request{Tag: "../../etc/passwd", Confirm: true}, ErrBadTag},
		{Request{Tag: "v0.5.0", Confirm: true}, ErrSame},
		{Request{Tag: "v0.7.0", Confirm: true}, ErrNotFound},
	} {
		if _, err := r.m.Apply(ctx, tc.req); !errors.Is(err, tc.want) {
			t.Errorf("%+v: err = %v, want %v", tc.req, err, tc.want)
		}
	}
	if r.stateExists() || r.stopped.Load() != 0 {
		t.Fatal("a refused upgrade changed something")
	}
}

// Bad signature, bad checksum, a missing signature asset, and a binary that
// fails its start check all abort with no change on disk and no shutdown.
func TestApplyAbortsWithNoChange(t *testing.T) {
	for _, tc := range []struct {
		name string
		prep func(*fakeRelease)
		want error
	}{
		{"bad signature", func(f *fakeRelease) { f.badSig = true }, ErrVerify},
		{"bad checksum", func(f *fakeRelease) { f.badSum = true }, ErrVerify},
		{"no signature asset", func(f *fakeRelease) { f.missing["v0.6.0"] = true }, ErrNotInstall},
		{"wrong version binary", func(f *fakeRelease) { f.bins["v0.6.0"] = script("0.9.9") }, ErrTrial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, "v0.6.0")
			tc.prep(f)
			r := newRig(t, f, "0.5.0")
			r.noHA()
			_, err := r.m.Apply(context.Background(), Request{Tag: "v0.6.0", Confirm: true})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			time.Sleep(20 * time.Millisecond)
			if r.stateExists() || r.stopped.Load() != 0 {
				t.Fatal("state written or shutdown requested")
			}
			if _, ok := r.m.Pending(); ok {
				t.Fatal("pending set")
			}
			if _, err := os.Stat(filepath.Join(r.dir, "versions", "0.6.0")); err == nil {
				t.Fatal("rejected binary left staged")
			}
			if r.m.Status().LastError == "" {
				t.Fatal("failure not reported")
			}
		})
	}
}

func TestApplyChecksNewBinaryAgainstConfig(t *testing.T) {
	f := newFake(t, "v0.6.0")
	r := newRig(t, f, "0.5.0")
	r.noHA()
	// The real trial runs the staged script with -version and -check.
	r.m.opt.Trial = func(ctx context.Context, path, version string) error {
		return defaultTrial(ctx, path, version, "/etc/packeteer/config.yaml", []string{"CHECK_EXIT=3"})
	}
	_, err := r.m.Apply(context.Background(), Request{Tag: "v0.6.0", Confirm: true})
	if !errors.Is(err, ErrTrial) || !strings.Contains(err.Error(), "-check") {
		t.Fatalf("err = %v", err)
	}
	if r.stateExists() {
		t.Fatal("state written")
	}
	r.m.opt.Trial = func(ctx context.Context, path, version string) error {
		return defaultTrial(ctx, path, version, "/etc/packeteer/config.yaml", nil)
	}
	if _, err := r.m.Apply(context.Background(), Request{Tag: "v0.6.0", Confirm: true}); err != nil {
		t.Fatal(err)
	}
}

func TestHAOrder(t *testing.T) {
	f := newFake(t, "v0.6.0")
	r := newRig(t, f, "0.5.0")
	ctx := context.Background()
	req := Request{Tag: "v0.6.0", Confirm: true}

	r.ha = &plugin.ElectorStatus{Role: plugin.RoleActive, Holder: "pk-a"}
	if _, err := r.m.Apply(ctx, req); !errors.Is(err, ErrHA) || !strings.Contains(err.Error(), "standby first") {
		t.Fatalf("active without confirmation: %v", err)
	}
	r.ha = &plugin.ElectorStatus{Role: plugin.RoleStandby}
	if _, err := r.m.Apply(ctx, req); !errors.Is(err, ErrHA) || !strings.Contains(err.Error(), "no node holds the lease") {
		t.Fatalf("standby with no active node: %v", err)
	}
	if r.stateExists() || r.stopped.Load() != 0 {
		t.Fatal("a refused upgrade changed something")
	}
	// The standby goes first.
	r.ha = &plugin.ElectorStatus{Role: plugin.RoleStandby, Holder: "pk-a"}
	if _, err := r.m.Apply(ctx, req); err != nil {
		t.Fatal(err)
	}
	// Then the active node, once the operator confirms the standby runs it.
	r2 := newRig(t, f, "0.5.0")
	r2.ha = &plugin.ElectorStatus{Role: plugin.RoleActive, Holder: "pk-a"}
	req.StandbyUpgraded = true
	if _, err := r2.m.Apply(ctx, req); err != nil {
		t.Fatal(err)
	}
}

func TestRollbackReturnsToThePreviousVersion(t *testing.T) {
	f := newFake(t, "v0.6.0")
	r := newRig(t, f, "0.5.0")
	r.noHA()
	ctx := context.Background()
	if _, err := r.m.Rollback(ctx, Request{Confirm: true}); !errors.Is(err, ErrNoPrevious) {
		t.Fatalf("rollback with nothing to go back to: %v", err)
	}
	if _, err := r.m.Apply(ctx, Request{Tag: "v0.6.0", Confirm: true}); err != nil {
		t.Fatal(err)
	}
	r.waitStop(t)

	// Restart as the staged version: it reads the base from the state.
	opt := r.m.opt
	opt.Version, opt.Exe = "0.6.0", filepath.Join(r.dir, "versions", "0.6.0", "packeteer")
	m2, err := New(opt, true)
	if err != nil {
		t.Fatal(err)
	}
	m2.Confirm()
	if st, _ := m2.store.load(); !st.Confirmed || st.Attempts != 0 {
		t.Fatalf("not confirmed: %+v", st)
	}
	if _, err := m2.Rollback(ctx, Request{}); !errors.Is(err, ErrNoConfirm) {
		t.Fatalf("rollback without confirmation: %v", err)
	}
	res, err := m2.Rollback(ctx, Request{Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "0.6.0" || res.To != "0.5.0" {
		t.Fatalf("result = %+v", res)
	}
	tg, _ := m2.Pending()
	if tg.Path != r.base || strings.Contains(strings.Join(tg.Env, "\n"), LaunchedEnv) {
		t.Fatalf("rollback target = %+v", tg)
	}
	st, _ := m2.store.load()
	if st.Active.Path != r.base || st.Previous.Version != "0.6.0" {
		t.Fatalf("state = %+v", st)
	}
	// The installed binary is untouched through all of it.
	if b, _ := os.ReadFile(r.base); string(b) != script("0.5.0") {
		t.Fatal("the installed binary changed")
	}
}

func TestRelaunch(t *testing.T) {
	f := newFake(t, "v0.6.0")
	r := newRig(t, f, "0.5.0")
	r.noHA()
	now := time.Now()
	env := []string{"A=b"}
	// No state: run as installed.
	if _, ok := Relaunch(r.dir, "0.5.0", r.base, env, quiet, now); ok {
		t.Fatal("relaunch with no state")
	}
	if _, err := r.m.Apply(context.Background(), Request{Tag: "v0.6.0", Confirm: true}); err != nil {
		t.Fatal(err)
	}
	// Attempt 1 was counted by the apply; the next start (after a crash)
	// is attempt 2 and still tries the new version.
	tg, ok := Relaunch(r.dir, "0.5.0", r.base, env, quiet, now)
	if !ok || tg.Version != "0.6.0" || !strings.Contains(strings.Join(tg.Env, " "), LaunchedEnv+"=0.6.0") {
		t.Fatalf("relaunch = %+v %v", tg, ok)
	}
	// It never confirmed: the third start goes back to the installed one.
	if _, ok := Relaunch(r.dir, "0.5.0", r.base, env, quiet, now); ok {
		t.Fatal("a version that never stayed up was started a third time")
	}
	st, _ := r.m.store.load()
	if st.Active.Path != r.base || st.LastError == "" {
		t.Fatalf("state after revert = %+v", st)
	}
	if got := r.m.Status(); !strings.Contains(got.LastError, "did not stay up") {
		t.Fatalf("status = %+v", got)
	}
}

func TestRelaunchRefusesTamperedAndStale(t *testing.T) {
	f := newFake(t, "v0.6.0")
	r := newRig(t, f, "0.5.0")
	r.noHA()
	if _, err := r.m.Apply(context.Background(), Request{Tag: "v0.6.0", Confirm: true}); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(r.dir, "versions", "0.6.0", "packeteer")
	if err := os.WriteFile(staged, []byte("#!/bin/sh\necho evil\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := Relaunch(r.dir, "0.5.0", r.base, nil, quiet, time.Now()); ok {
		t.Fatal("a staged binary that changed on disk was started")
	}
	// A new image (another base version) discards the state.
	r2 := newRig(t, f, "0.5.0")
	r2.noHA()
	if _, err := r2.m.Apply(context.Background(), Request{Tag: "v0.6.0", Confirm: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := Relaunch(r2.dir, "0.7.0", r2.base, nil, quiet, time.Now()); ok {
		t.Fatal("state for another base version was used")
	}
	if r2.stateExists() {
		t.Fatal("stale state kept")
	}
}

func TestAbortRestoresTheState(t *testing.T) {
	f := newFake(t, "v0.6.0")
	r := newRig(t, f, "0.5.0")
	r.noHA()
	if _, err := r.m.Apply(context.Background(), Request{Tag: "v0.6.0", Confirm: true}); err != nil {
		t.Fatal(err)
	}
	r.m.Abort("shutdown did not finish")
	if _, ok := r.m.Pending(); ok {
		t.Fatal("still pending")
	}
	st, _ := r.m.store.load()
	if st.Active.Path != r.base || st.LastError == "" {
		t.Fatalf("state = %+v", st)
	}
}

func TestRefusesPlainHTTPAndOtherSchemes(t *testing.T) {
	for _, u := range []string{"http://example.net/x", "file:///etc/passwd", "ftp://example.net/x"} {
		if _, err := allowedURL(u); err == nil {
			t.Errorf("allowedURL(%q) accepted", u)
		}
	}
	for _, u := range []string{"https://example.net/x", "http://127.0.0.1:9/x", "http://localhost/x"} {
		if _, err := allowedURL(u); err != nil {
			t.Errorf("allowedURL(%q): %v", u, err)
		}
	}
}
