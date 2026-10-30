package ripe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const (
	user = "EXAMPLE-MNT"
	pass = "not-a-real-password"
)

type request struct {
	method, path, query, user, pass string
	body                            string
}

func newPusher(t *testing.T, cfg string, h http.HandlerFunc, creds bool) *Pusher {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(strings.ReplaceAll(cfg, "SRV", srv.URL)), &node); err != nil {
		t.Fatal(err)
	}
	env := plugin.Env{Getenv: func(k string) string {
		switch {
		case !creds:
			return ""
		case k == UserEnv:
			return user
		case k == PasswordEnv:
			return pass
		}
		return ""
	}}
	c, err := New(plugin.NewConfig(node.Content[0]), env)
	if err != nil {
		t.Fatal(err)
	}
	p := c.(*Pusher)
	p.http = srv.Client()
	p.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	p.limit = rate.NewLimiter(rate.Inf, 1)
	return p
}

const routeObj = "route:          203.0.113.0/24\ndescr:          Announced by AS64496\norigin:         AS64496\nmnt-by:         EXAMPLE-MNT\nsource:         RIPE\n"

func create() plugin.RegistryChange {
	return plugin.RegistryChange{Registry: "ripe", Op: "create_object", Class: "route", Key: "203.0.113.0/24AS64496", Object: routeObj}
}

// #289: a create is a POST of the object as REST JSON to the database and
// class, with the maintainer credentials as basic auth; a delete is a
// DELETE of the key.
func TestPush(t *testing.T) {
	var got []request
	p := newPusher(t, "{base_url: SRV}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u, pw, _ := r.BasicAuth()
		got = append(got, request{r.Method, r.URL.Path, r.URL.RawQuery, u, pw, string(b)})
		w.WriteHeader(http.StatusOK)
	}, true)
	ctx := context.Background()
	if err := p.Push(ctx, create()); err != nil {
		t.Fatal(err)
	}
	del := plugin.RegistryChange{Registry: "ripe", Op: "delete_object", Class: "route", Key: "203.0.113.0/24AS64496", Object: routeObj}
	if err := p.Push(ctx, del); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("requests = %+v", got)
	}
	c := got[0]
	if c.method != "POST" || c.path != "/ripe/route" || c.user != user || c.pass != pass {
		t.Fatalf("create = %+v", c)
	}
	var doc struct {
		Objects struct {
			Object []struct {
				Source     struct{ ID string }
				Attributes struct {
					Attribute []struct{ Name, Value string }
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(c.body), &doc); err != nil || len(doc.Objects.Object) != 1 {
		t.Fatalf("body %q: %v", c.body, err)
	}
	o := doc.Objects.Object[0]
	var names []string
	for _, a := range o.Attributes.Attribute {
		names = append(names, a.Name+"="+a.Value)
	}
	want := "route=203.0.113.0/24 descr=Announced by AS64496 origin=AS64496 mnt-by=EXAMPLE-MNT source=RIPE"
	if o.Source.ID != "RIPE" || strings.Join(names, " ") != want {
		t.Fatalf("object = %+v (%s)", o, names)
	}
	d := got[1]
	if d.method != "DELETE" || d.path != "/ripe/route/203.0.113.0/24AS64496" || !strings.HasPrefix(d.query, "reason=") || d.user != user {
		t.Fatalf("delete = %+v", d)
	}
}

// #289: the TEST database is addressed by its own path and the object must
// name it.
func TestTestDatabase(t *testing.T) {
	var path string
	p := newPusher(t, "{base_url: SRV, source: test}", func(w http.ResponseWriter, r *http.Request) { path = r.URL.Path }, true)
	ch := create()
	if err := p.Push(context.Background(), ch); err == nil || !strings.Contains(err.Error(), "source is not TEST") {
		t.Fatalf("RIPE object into TEST = %v", err)
	}
	ch.Object = strings.Replace(routeObj, "source:         RIPE", "source:         TEST", 1)
	if err := p.Push(context.Background(), ch); err != nil || path != "/test/route" {
		t.Fatalf("test db = %v path %q", err, path)
	}
}

// #289: nothing is sent without credentials, for an object that does not
// match its key or is not exactly one object, or for another change; a
// rejected request and a redirect are errors that do not leak the password.
func TestPushRefusals(t *testing.T) {
	var n int
	redirect := false
	p := newPusher(t, "{base_url: SRV}", func(w http.ResponseWriter, r *http.Request) {
		n++
		if redirect {
			http.Redirect(w, r, "https://other.example.net/", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}, true)
	ctx := context.Background()

	bad := map[string]func(*plugin.RegistryChange){
		"key mismatch": func(c *plugin.RegistryChange) { c.Key = "198.51.100.0/24AS64496" },
		"two objects":  func(c *plugin.RegistryChange) { c.Object = routeObj + "\n" + routeObj },
		"class":        func(c *plugin.RegistryChange) { c.Class = "route6" },
		"no object":    func(c *plugin.RegistryChange) { c.Object = "" },
	}
	for name, mut := range bad {
		ch := create()
		mut(&ch)
		if err := p.Push(ctx, ch); err == nil || err == plugin.ErrRegistryNoPush {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for name, mut := range map[string]func(*plugin.RegistryChange){
		"other registry": func(c *plugin.RegistryChange) { c.Registry = "peeringdb" },
		"other op":       func(c *plugin.RegistryChange) { c.Op = "update_field" },
		"as-set":         func(c *plugin.RegistryChange) { c.Class = "as-set" },
	} {
		ch := create()
		mut(&ch)
		if err := p.Push(ctx, ch); err != plugin.ErrRegistryNoPush {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if n != 0 {
		t.Fatalf("%d requests for refused changes", n)
	}
	if err := p.Push(ctx, create()); err == nil || !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), pass) {
		t.Fatalf("403 = %v", err)
	}
	redirect = true
	if err := p.Push(ctx, create()); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect = %v", err)
	}

	np := newPusher(t, "{base_url: SRV}", func(http.ResponseWriter, *http.Request) { n++ }, false)
	n = 0
	if err := np.Push(ctx, create()); err == nil || !strings.Contains(err.Error(), "PACKETEER_RIPE_PASSWORD") || n != 0 {
		t.Fatalf("no credentials = %v, %d requests", err, n)
	}
	if fs, err := np.Check(ctx, plugin.RegistryFacts{}); err != nil || fs != nil {
		t.Fatalf("Check = %v %v", fs, err)
	}
}

// #289: the config is checked at load time and needs no credentials.
func TestConfig(t *testing.T) {
	for cfg, bad := range map[string]bool{
		"{}":                                  false,
		"{source: ripe}":                      false,
		"{source: radb}":                      true,
		"{base_url: 'http://x.example'}":      true,
		"{base_url: 'https://u:p@x.example'}": true,
		"{timeout: 1ms}":                      true,
		"{token: x}":                          true,
	} {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(cfg), &node); err != nil {
			t.Fatal(err)
		}
		_, err := New(plugin.NewConfig(node.Content[0]), plugin.Env{})
		if (err != nil) != bad {
			t.Errorf("%s: err = %v", cfg, err)
		}
	}
}
