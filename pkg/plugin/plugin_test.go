package plugin

import (
	"context"
	"strings"
	"testing"
)

type fakeNotifier struct{ Base }

func (fakeNotifier) Notify(context.Context, Event) error { return nil }

func TestRegistry(t *testing.T) {
	r := NewRegistry[Notifier](KindNotifier)
	r.Register("b", func(Config, Env) (Notifier, error) { return fakeNotifier{}, nil })
	r.Register("a", func(Config, Env) (Notifier, error) { return fakeNotifier{}, nil })
	if got := strings.Join(r.Types(), ","); got != "a,b" {
		t.Errorf("Types = %s", got)
	}
	if !r.Has("a") || r.Has("zzz") {
		t.Error("Has wrong")
	}
	if _, err := r.New("a", Config{}, Env{}); err != nil {
		t.Errorf("New: %v", err)
	}
	_, err := r.New("zzz", Config{}, Env{})
	if err == nil || !strings.Contains(err.Error(), `unknown notifier type "zzz" (available: a, b)`) {
		t.Errorf("err = %v", err)
	}
}

func TestRegistryEmptyAvailable(t *testing.T) {
	r := NewRegistry[Scorer](KindScorer)
	_, err := r.New("x", Config{}, Env{})
	if err == nil || !strings.Contains(err.Error(), "available: none") {
		t.Errorf("err = %v", err)
	}
}

func TestRegistryPanics(t *testing.T) {
	r := NewRegistry[Notifier](KindNotifier)
	f := func(Config, Env) (Notifier, error) { return fakeNotifier{}, nil }
	r.Register("a", f)
	for name, fn := range map[string]func(){
		"duplicate": func() { r.Register("a", f) },
		"empty":     func() { r.Register("", f) },
		"nil":       func() { r.Register("c", nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic")
				}
			}()
			fn()
		})
	}
}

func TestConfigDecode(t *testing.T) {
	type cfg struct {
		URL   string `yaml:"url"`
		Count int    `yaml:"count"`
	}
	tests := []struct {
		name    string
		yaml    string
		want    cfg
		wantErr string
	}{
		{"valid", "url: http://x\ncount: 3", cfg{"http://x", 3}, ""},
		{"empty", "", cfg{}, ""},
		{"unknown field", "url: x\nbogus: 1", cfg{}, "field bogus not found"},
		{"wrong type", "count: many", cfg{}, "cannot unmarshal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ConfigFromYAML(tt.yaml)
			if err != nil {
				t.Fatal(err)
			}
			var got cfg
			err = c.Decode(&got)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}

func TestConfigRaw(t *testing.T) {
	c, _ := ConfigFromYAML("a: 1\nb: [x, y]")
	v, err := c.Raw()
	if err != nil {
		t.Fatal(err)
	}
	m, ok := v.(map[string]any)
	if !ok || m["a"] != 1 {
		t.Fatalf("Raw = %#v", v)
	}
	if v, _ := (Config{}).Raw(); v != nil {
		t.Errorf("zero Raw = %v", v)
	}
}
