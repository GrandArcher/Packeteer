package offload

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeReader struct{}

func (fakeReader) Read(context.Context, Dimension) (Reading, error) {
	return Reading{Known: false}, nil
}

func TestCheckRun(t *testing.T) {
	cases := []struct {
		name    string
		profile Profile
		req     RunLevel
		want    RunLevel
		wantErr string
	}{
		{"none report", NoneProfile(), Report, Report, ""},
		{"none refuse", NoneProfile(), Refuse, Refuse, ""},
		{"none dry run", NoneProfile(), DryRun, Refuse, "allows at most report"},
		{"none enforce", NoneProfile(), Enforce, Refuse, "allows at most report"},
		{"refuse refuse", RefuseProfile(), Refuse, Refuse, ""},
		{"refuse report", RefuseProfile(), Report, Refuse, "platform not supported, nothing evaluated"},
		{"refuse enforce", RefuseProfile(), Enforce, Refuse, "allows at most refuse"},
		{"enforce profile dry run", Profile{ID: "x", MaxRun: Enforce}, DryRun, DryRun, ""},
		{"enforce profile enforce", Profile{ID: "x", MaxRun: Enforce}, Enforce, Enforce, ""},
		{"dry run profile enforce", Profile{ID: "x", MaxRun: DryRun}, Enforce, Refuse, "allows at most dry_run"},
		{"negative level", NoneProfile(), RunLevel(-1), Refuse, "unknown level"},
		{"level above enforce", Profile{ID: "x", MaxRun: Enforce}, RunLevel(9), Refuse, "unknown level"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := CheckRun(c.profile, c.req)
			if got != c.want {
				t.Errorf("level = %s, want %s", got, c.want)
			}
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want ErrRefused containing %q", err, c.wantErr)
			}
		})
	}
}

func TestRunLevelString(t *testing.T) {
	for l, want := range map[RunLevel]string{
		Refuse: "refuse", Report: "report", DryRun: "dry_run", Enforce: "enforce", RunLevel(7): "run_level(7)",
	} {
		if got := l.String(); got != want {
			t.Errorf("RunLevel(%d) = %q, want %q", int(l), got, want)
		}
	}
}

func TestBuiltinProfiles(t *testing.T) {
	none := NoneProfile()
	if none.ID != "none" || none.MaxRun != Report || none.DefaultPolicy.Kind != NotApplicable ||
		!strings.Contains(none.DefaultPolicy.Reason, "not applicable") || none.Miss != Unknown {
		t.Errorf("none profile = %+v", none)
	}
	ref := RefuseProfile()
	if ref.ID != "refuse" || ref.Status != Unverified || ref.MaxRun != Refuse ||
		ref.DefaultPolicy.Reason != "platform not supported, nothing evaluated" || ref.Miss != Unknown {
		t.Errorf("refuse profile = %+v", ref)
	}
	for _, p := range []Profile{none, ref} {
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", p.ID, err)
		}
		if p.Reader != nil || len(p.Dimensions) != 0 {
			t.Errorf("%s measures nothing but has a reader or dimensions", p.ID)
		}
	}
}

func TestValidate(t *testing.T) {
	good := func() Profile {
		p := NoneProfile()
		p.ID = "x"
		return p
	}
	cases := []struct {
		name    string
		mutate  func(*Profile)
		wantErr string
	}{
		{"ok", func(*Profile) {}, ""},
		{"ok with reader at enforce", func(p *Profile) { p.MaxRun = Enforce; p.Reader = fakeReader{} }, ""},
		{"no id", func(p *Profile) { p.ID = "" }, "no id"},
		{"bad status", func(p *Profile) { p.Status = "maybe" }, "unknown status"},
		{"bad run level", func(p *Profile) { p.MaxRun = RunLevel(5) }, "unknown max run level"},
		{"bad policy", func(p *Profile) { p.DefaultPolicy.Kind = "x" }, "unknown default policy"},
		{"no reason", func(p *Profile) { p.DefaultPolicy.Reason = "" }, "no reason"},
		{"bad miss", func(p *Profile) { p.Miss = "x" }, "unknown miss"},
		{"bad selection", func(p *Profile) { p.Selection = "x" }, "unknown selection"},
		{"unverified above refuse", func(p *Profile) { p.Status = Unverified }, "must be refuse"},
		{"dry run without reader", func(p *Profile) { p.MaxRun = DryRun }, "needs a reader"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := good()
			c.mutate(&p)
			err := p.Validate()
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, c.wantErr)
			}
		})
	}
}

func TestRegistryGet(t *testing.T) {
	r := NewRegistry()
	for _, id := range []string{"none", "refuse"} {
		p, err := r.Get(id)
		if err != nil || p.ID != id {
			t.Errorf("Get(%q) = %+v, %v", id, p, err)
		}
	}
	for _, id := range []string{"", "nokia-7750", "None", "refuse "} {
		p, err := r.Get(id)
		if !errors.Is(err, ErrUnknownProfile) {
			t.Errorf("Get(%q) err = %v, want ErrUnknownProfile", id, err)
		}
		if !reflect.DeepEqual(p, Profile{}) {
			t.Errorf("Get(%q) returned a profile for an unknown id: %+v", id, p)
		}
	}
}

func TestRegistryRegister(t *testing.T) {
	r := NewRegistry()
	p := NoneProfile()
	p.ID = "lab-switch"
	if err := r.Register(p); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get("lab-switch")
	if err != nil || got.ID != "lab-switch" {
		t.Fatalf("Get after Register = %+v, %v", got, err)
	}
	if err := r.Register(p); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("duplicate Register err = %v", err)
	}
	if err := r.Register(NoneProfile()); err == nil {
		t.Error("re-registering the built-in none profile was accepted")
	}
	bad := p
	bad.ID = "bad"
	bad.Miss = "x"
	if err := r.Register(bad); err == nil {
		t.Error("an invalid profile was registered")
	}
	if _, err := r.Get("bad"); !errors.Is(err, ErrUnknownProfile) {
		t.Errorf("rejected profile is retrievable: %v", err)
	}
}

func TestRegistryIDs(t *testing.T) {
	r := NewRegistry()
	if got, want := r.IDs(), []string{"none", "refuse"}; !reflect.DeepEqual(got, want) {
		t.Errorf("IDs = %v, want %v", got, want)
	}
	p := NoneProfile()
	p.ID = "alpha"
	if err := r.Register(p); err != nil {
		t.Fatal(err)
	}
	if got, want := r.IDs(), []string{"alpha", "none", "refuse"}; !reflect.DeepEqual(got, want) {
		t.Errorf("IDs = %v, want %v", got, want)
	}
}

// G23: a reader that cannot measure reports unknown, never a zero reading.
func TestReaderUnknownIsNotZero(t *testing.T) {
	var r Reader = fakeReader{}
	got, err := r.Read(context.Background(), FIBv4)
	if err != nil || got.Known || got.Used != 0 {
		t.Fatalf("Read = %+v, %v", got, err)
	}
}
