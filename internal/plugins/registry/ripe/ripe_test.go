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

// storedObj is a database object whose descr, mnt-by, mnt-routes, and
// remarks differ from what Packeteer would write, as a whois answer and as
// the REST API returns it.
const storedObj = "route:          203.0.113.0/24\n" +
	"descr:          Customer link, moved in 2025\n" +
	"origin:         AS64496\n" +
	"mnt-by:         OTHER-MNT\n" +
	"mnt-routes:     ROUTES-MNT\n" +
	"remarks:        keep until the contract ends\n" +
	"remarks:        second line,\n" +
	"                continued\n" +
	"source:         RIPE # Filtered\n"

const storedREST = `{"objects":{"object":[{"type":"route","source":{"id":"ripe"},"attributes":{"attribute":[
{"name":"route","value":"203.0.113.0/24"},
{"name":"descr","value":"Customer link, moved in 2025"},
{"name":"origin","value":"AS64496"},
{"link":{"type":"locator","href":"https://rest.db.ripe.net/ripe/mntner/OTHER-MNT"},"name":"mnt-by","value":"OTHER-MNT","referenced-type":"mntner"},
{"name":"mnt-routes","value":"ROUTES-MNT","referenced-type":"mntner"},
{"name":"remarks","value":"keep until the contract ends"},
{"name":"remarks","value":"second line, continued"},
{"name":"source","value":"RIPE"}]}}]}}`

func deletion() plugin.RegistryChange {
	return plugin.RegistryChange{Registry: "ripe", Op: "delete_object", Class: "route", Key: "203.0.113.0/24AS64496", Object: storedObj}
}

// #289: a create is a POST of the object as REST JSON to the database and
// class, with the maintainer credentials as basic auth; a delete first
// reads the stored object without credentials, then DELETEs the key.
func TestPush(t *testing.T) {
	var got []request
	p := newPusher(t, "{base_url: SRV}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u, pw, _ := r.BasicAuth()
		got = append(got, request{r.Method, r.URL.Path, r.URL.RawQuery, u, pw, string(b)})
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, storedREST)
		}
	}, true)
	ctx := context.Background()
	if err := p.Push(ctx, create()); err != nil {
		t.Fatal(err)
	}
	if err := p.Push(ctx, deletion()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("requests = %+v", got)
	}
	if g := got[1]; g.method != "GET" || g.path != "/ripe/route/203.0.113.0/24AS64496" || g.query != "unfiltered" || g.user != "" || g.pass != "" {
		t.Fatalf("read before delete = %+v", g)
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
	d := got[2]
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

// #289: a delete is refused, and nothing is deleted, when the stored object
// is gone, differs from the one shown, or cannot be read.
func TestDeleteNeedsTheShownObject(t *testing.T) {
	var deletes int
	answer, code := storedREST, http.StatusOK
	p := newPusher(t, "{base_url: SRV}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes++
			return
		}
		w.WriteHeader(code)
		_, _ = io.WriteString(w, answer)
	}, true)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		answer string
		code   int
		want   string
	}{
		"descr changed": {strings.Replace(storedREST, "moved in 2025", "moved in 2026", 1), http.StatusOK, "differs from the object shown"},
		"remark added":  {strings.Replace(storedREST, `{"name":"source"`, `{"name":"remarks","value":"new"},{"name":"source"`, 1), http.StatusOK, "differs from the object shown"},
		"gone":          {`{"errormessages":{}}`, http.StatusNotFound, "no longer in the database"},
		"not json":      {"<html>", http.StatusOK, "not one REST object"},
		"server error":  {"", http.StatusInternalServerError, "HTTP 500"},
	} {
		answer, code = tc.answer, tc.code
		if err := p.Push(ctx, deletion()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// The template object is not what the database holds.
	answer, code = storedREST, http.StatusOK
	ch := deletion()
	ch.Object = routeObj
	if err := p.Push(ctx, ch); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("template object = %v", err)
	}
	if deletes != 0 {
		t.Fatalf("%d deletes after refusals", deletes)
	}
}
