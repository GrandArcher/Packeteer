package configedit

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

const observeYAML = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
`

const injectYAML = `mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 5m
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
allowlist:
  prefixes: [198.51.100.0/24]
bgp:
  neighbors:
    - address: 192.0.2.254
announcer:
  type: gobgp
`

func parse(data []byte) (*config.Config, error) { return config.Parse(data) }

func editor(t *testing.T, content string) (*Editor, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	running, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	diff := func(a, b *config.Config) ([]string, bool) {
		var keys []string
		if a.Mode != b.Mode {
			keys = append(keys, "mode")
		}
		if a.ASN != b.ASN {
			keys = append(keys, "asn")
		}
		return keys, !reflect.DeepEqual(a.BGP.Neighbors, b.BGP.Neighbors)
	}
	e, err := New(path, running, parse, diff)
	if err != nil {
		t.Fatal(err)
	}
	return e, path
}

func TestSaveRoundTripsThroughLoad(t *testing.T) {
	e, path := editor(t, observeYAML)
	f, err := e.Read()
	if err != nil || f.YAML != observeYAML || f.SHA256 != Hash([]byte(observeYAML)) {
		t.Fatalf("read = %+v %v", f, err)
	}
	next := strings.Replace(observeYAML, "asn: 64512", "asn: 64513", 1) + "# edited\n"
	saved, res, err := e.Save([]byte(next), f.SHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || !res.RestartRequired || !reflect.DeepEqual(res.Changed, []string{"asn"}) || res.ReloadOnline {
		t.Fatalf("result = %+v", res)
	}
	disk, _ := os.ReadFile(path)
	if string(disk) != next || saved.SHA256 != Hash(disk) {
		t.Fatalf("disk = %q", disk)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := config.Parse([]byte(next))
	if !reflect.DeepEqual(loaded, want) || loaded.ASN != 64513 {
		t.Fatalf("round trip: loaded %+v", loaded)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Fatalf("file mode %v not kept", st.Mode().Perm())
	}
	// No temporary files are left next to it.
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Fatalf("dir has %d entries", len(ents))
	}
}

func TestSaveRefusesInvalidAndKeepsFile(t *testing.T) {
	e, path := editor(t, observeYAML)
	base := Hash([]byte(observeYAML))
	for _, bad := range []string{
		"mode: observe\n",                                    // missing fields
		observeYAML + "bogus_key: 1\n",                       // unknown key
		strings.Replace(observeYAML, "observe", "inject", 1), // inject without its requirements
		"mode: [\n", // not YAML
		strings.Repeat("#", MaxSize+1),
	} {
		_, res, err := e.Save([]byte(bad), base, true)
		if err == nil || res.Valid || len(res.Errors) == 0 {
			t.Fatalf("saved invalid config %.40q: %+v %v", bad, res, err)
		}
		if bad != strings.Repeat("#", MaxSize+1) && !errors.Is(err, ErrInvalid) {
			t.Fatalf("err = %v", err)
		}
	}
	disk, _ := os.ReadFile(path)
	if string(disk) != observeYAML {
		t.Fatal("file changed by a refused save")
	}
}

func TestSaveConflict(t *testing.T) {
	e, path := editor(t, observeYAML)
	if _, _, err := e.Save([]byte(observeYAML), "", false); !errors.Is(err, ErrConflict) {
		t.Fatalf("empty base: %v", err)
	}
	if err := os.WriteFile(path, []byte(observeYAML+"# someone else\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.Save([]byte(observeYAML), Hash([]byte(observeYAML)), false); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale base: %v", err)
	}
}

func TestSaveInjectNeedsConfirmation(t *testing.T) {
	e, path := editor(t, observeYAML)
	base := Hash([]byte(observeYAML))
	res := e.Check([]byte(injectYAML))
	if !res.Valid || !res.EnablesInject || res.Mode != config.ModeInject {
		t.Fatalf("check = %+v", res)
	}
	if _, _, err := e.Save([]byte(injectYAML), base, false); !errors.Is(err, ErrConfirmInject) {
		t.Fatalf("unconfirmed inject: %v", err)
	}
	if disk, _ := os.ReadFile(path); string(disk) != observeYAML {
		t.Fatal("file changed")
	}
	if _, res, err := e.Save([]byte(injectYAML), base, true); err != nil || !res.ReloadOnline {
		t.Fatalf("confirmed inject: %+v %v", res, err)
	}
	// Already inject on disk: an edit that keeps inject needs no confirmation.
	if _, _, err := e.Save([]byte(injectYAML+"# note\n"), Hash([]byte(injectYAML)), false); err != nil {
		t.Fatalf("keep inject: %v", err)
	}
}

// A single-file bind mount cannot be renamed over; a read-only directory
// has the same effect. The editor then rewrites the file in place.
func TestSaveInPlaceWhenDirectoryIsReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	e, path := editor(t, observeYAML)
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	next := observeYAML + "# in place\n"
	if _, _, err := e.Save([]byte(next), Hash([]byte(observeYAML)), false); err != nil {
		t.Fatal(err)
	}
	if disk, _ := os.ReadFile(path); string(disk) != next {
		t.Fatalf("disk = %q", disk)
	}
}

func TestWizard(t *testing.T) {
	in := WizardInput{
		ASN: 64512, RouterID: "192.0.2.10", Edge: "192.0.2.254",
		Providers: []WizardProvider{{"transit-a", "192.0.2.11", "192.0.2.1"}, {"transit-b", "192.0.2.12", "192.0.2.2"}},
		Prefix:    "198.51.100.0/24", Host: "198.51.100.10",
		Storage: true,
	}
	out, err := Wizard(in)
	if err != nil {
		t.Fatal(err)
	}
	// Round trip: the controller's loader accepts it as written.
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if cfg.Mode != config.ModeObserve || len(cfg.Allowlist.Prefixes) != 0 || cfg.Announcer != nil {
		t.Fatalf("wizard config can announce: mode %s allowlist %v announcer %v", cfg.Mode, cfg.Allowlist.Prefixes, cfg.Announcer)
	}
	if len(cfg.Providers) != 2 || cfg.Providers[1].NextHop != "192.0.2.2" || len(cfg.BGP.Neighbors) != 1 || cfg.BGP.Neighbors[0].Address != "192.0.2.254" ||
		cfg.Storage == nil || cfg.PacketeerCommunity != "64512:666" || cfg.HTTPListen() != config.DefaultHTTPListen {
		t.Fatalf("wizard config = %+v", cfg)
	}
	if !strings.Contains(string(out), "host: 198.51.100.10") || strings.Contains(string(out), "mode: inject") || strings.Contains(string(out), "announcer:") {
		t.Fatalf("yaml missing pin or can announce:\n%s", out)
	}
	if !strings.HasPrefix(string(out), "# Generated by the Packeteer setup wizard") {
		t.Fatal("header missing")
	}
	// A prefix without a pin is still observe, and the host line is absent
	// so probes use the first address of the prefix.
	bare, err := Wizard(WizardInput{ASN: 64512, RouterID: "192.0.2.10", Edge: "192.0.2.254",
		Providers: []WizardProvider{{"transit-a", "192.0.2.11", "192.0.2.1"}}, Prefix: "198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bare), "host:") || !strings.Contains(string(bare), "prefix: 198.51.100.0/24") {
		t.Fatalf("unpinned prefix:\n%s", bare)
	}
	// No probe prefix: still a learn-only edge, no static source, no announcer.
	none, err := Wizard(WizardInput{ASN: 64512, RouterID: "192.0.2.10", Edge: "192.0.2.254",
		Providers: []WizardProvider{{"transit-a", "192.0.2.11", "192.0.2.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Parse(none)
	if err != nil || cfg.Mode != config.ModeObserve || cfg.Announcer != nil || len(cfg.Sources) != 0 || len(cfg.BGP.Neighbors) != 1 {
		t.Fatalf("no probe: %v mode %s sources %d\n%s", err, cfg.Mode, len(cfg.Sources), none)
	}
}

func TestWizardErrors(t *testing.T) {
	good := WizardInput{ASN: 64512, RouterID: "192.0.2.10", Edge: "192.0.2.254",
		Providers: []WizardProvider{{"transit-a", "192.0.2.11", "192.0.2.1"}},
		Prefix:    "198.51.100.0/24", Host: "198.51.100.1"}
	for name, tc := range map[string]struct {
		mut  func(*WizardInput)
		want string
	}{
		"no providers":        {func(w *WizardInput) { w.Providers = nil }, "providers: 1 to"},
		"host without prefix": {func(w *WizardInput) { w.Prefix = ""; w.Host = "198.51.100.1" }, "requires a prefix"},
		"bad prefix":          {func(w *WizardInput) { w.Prefix = "x" }, "is not a prefix"},
		"host outside":        {func(w *WizardInput) { w.Host = "203.0.113.1" }, "must be an address inside"},
		"no asn":              {func(w *WizardInput) { w.ASN = 0 }, "asn is required"},
		"bad router id":       {func(w *WizardInput) { w.RouterID = "2001:db8::1" }, "router_id"},
		"bad next hop":        {func(w *WizardInput) { w.Providers[0].NextHop = "nope" }, "next_hop"},
		"no edge":             {func(w *WizardInput) { w.Edge = "" }, "edge is required"},
		"bad edge":            {func(w *WizardInput) { w.Edge = "nope" }, "not an IP address"},
		"inject":              {func(w *WizardInput) { w.Mode = "inject" }, "inject is not a step"},
		"suggest":             {func(w *WizardInput) { w.Mode = "suggest" }, "always starts in observe"},
		"newline in name":     {func(w *WizardInput) { w.Providers[0].Name = "a\nmode: inject" }, "one line"},
	} {
		in := good
		in.Providers = append([]WizardProvider(nil), good.Providers...)
		tc.mut(&in)
		if _, err := Wizard(in); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	// observe is the only mode the wizard accepts, and it still writes observe.
	in := good
	in.Providers = append([]WizardProvider(nil), good.Providers...)
	in.Mode = config.ModeObserve
	out, err := Wizard(in)
	if err != nil || !strings.Contains(string(out), "mode: observe") || strings.Contains(string(out), "mode: inject") {
		t.Fatalf("observe mode: %v\n%s", err, out)
	}
}

// overwrite writes over the old content and cuts the tail: a shorter
// file leaves nothing of the longer one behind.
func TestOverwriteInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(observeYAML+"# a long trailing comment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := overwrite(path, []byte("mode: observe\n")); err != nil {
		t.Fatal(err)
	}
	if disk, _ := os.ReadFile(path); string(disk) != "mode: observe\n" {
		t.Fatalf("disk = %q", disk)
	}
}

// When the in-place write and the restore both fail, the previous file
// is kept in a temporary file named in the error.
func TestWriteFileKeepsOldWhenRestoreFails(t *testing.T) {
	// No directory: the rename path fails, so writeFile falls back to
	// rewriting in place.
	path := filepath.Join(t.TempDir(), "missing", "config.yaml")
	old := []byte(observeYAML)
	real := overwrite
	t.Cleanup(func() { overwrite = real })

	calls := 0
	overwrite = func(string, []byte) error {
		calls++
		if calls == 1 {
			return errors.New("disk full")
		}
		return nil
	}
	if err := writeFile(path, []byte("mode: inject\n"), old); err == nil || err.Error() != "disk full" || calls != 2 {
		t.Fatalf("restored: err %v, calls %d", err, calls)
	}

	overwrite = func(string, []byte) error { return errors.New("disk full") }
	err := writeFile(path, []byte("mode: inject\n"), old)
	if err == nil || !strings.Contains(err.Error(), "restoring the previous file failed too") {
		t.Fatalf("err = %v", err)
	}
	_, saved, ok := strings.Cut(err.Error(), "the previous file is saved at ")
	if !ok {
		t.Fatalf("no copy named: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(saved) })
	if got, _ := os.ReadFile(saved); string(got) != string(old) {
		t.Fatalf("saved copy = %q", got)
	}
}
