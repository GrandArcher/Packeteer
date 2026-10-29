package nats

import (
	"context"
	"errors"
	"strings"
	"testing"

	natsgo "github.com/nats-io/nats.go"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func build(t *testing.T, y string) (plugin.Exporter, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"NUSER": "svc", "NPASS": "secret"}
	return plugin.Exporters.New(TypeName, c, plugin.Env{Name: "n", Getenv: func(k string) string { return env[k] }})
}

func TestConfigValidation(t *testing.T) {
	ok, err := build(t, "urls: [\"nats://nats.example.net:4222\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ok.Streams(), ","); got != "events,decisions" {
		t.Fatalf("default streams = %s, flows must be opt-in", got)
	}
	for name, y := range map[string]string{
		"no urls":          "subject_prefix: x\n",
		"wrong scheme":     "urls: [\"http://a:4222\"]\n",
		"no host":          "urls: [\"nats://\"]\n",
		"url credentials":  "urls: [\"nats://u:p@a:4222\"]\n",
		"tls url, no tls":  "urls: [\"tls://a:4222\"]\n",
		"wildcard prefix":  "urls: [\"nats://a:4222\"]\nsubject_prefix: \"a.*\"\n",
		"empty token":      "urls: [\"nats://a:4222\"]\nsubject_prefix: \"a..b\"\n",
		"bad stream":       "urls: [\"nats://a:4222\"]\nstreams: [traces]\n",
		"negative timeout": "urls: [\"nats://a:4222\"]\ntimeout: -1s\n",
		"user without tls": "urls: [\"nats://a:4222\"]\nusername_env: NUSER\npassword_env: NPASS\n",
		"only username":    "urls: [\"tls://a:4222\"]\ntls: true\nusername_env: NUSER\n",
		"unknown field":    "urls: [\"nats://a:4222\"]\ntoken: x\n",
	} {
		if _, err := build(t, y); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := build(t, "urls: [\"tls://a:4222\"]\ntls: true\nsubject_prefix: edge1.pk\nusername_env: NUSER\npassword_env: NPASS\n"); err != nil {
		t.Fatal(err)
	}
}

type fakeConn struct {
	subjects []string
	bodies   []string
	flushErr error
	closed   bool
}

func (f *fakeConn) Publish(s string, d []byte) error {
	f.subjects = append(f.subjects, s)
	f.bodies = append(f.bodies, string(d))
	return nil
}
func (f *fakeConn) FlushWithContext(context.Context) error { return f.flushErr }
func (f *fakeConn) Close()                                 { f.closed = true }

func TestExportPublishesJSONPerStream(t *testing.T) {
	x, err := build(t, "urls: [\"nats://a:4222\", \"nats://b:4222\"]\nsubject_prefix: edge1\nstreams: [decisions, flows]\n")
	if err != nil {
		t.Fatal(err)
	}
	n := x.(*Exporter)
	fc := &fakeConn{}
	var gotURLs string
	n.dial = func(u string, _ ...natsgo.Option) (conn, error) { gotURLs = u; return fc, nil }
	if err := x.Export(context.Background(), nil); err == nil {
		t.Fatal("export before Start must fail")
	}
	if err := x.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotURLs != "nats://a:4222,nats://b:4222" {
		t.Fatalf("urls = %q", gotURLs)
	}
	err = x.Export(context.Background(), []plugin.ExportRecord{
		{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{ID: "00000000000000ab", Prefix: "192.0.2.0/24", Provider: "transit-b"}},
		{Stream: plugin.StreamFlows, Flow: &plugin.FlowRecord{Prefix: "192.0.2.0/24", Bytes: 5}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(fc.subjects, ",") != "edge1.decisions,edge1.flows" {
		t.Fatalf("subjects = %v", fc.subjects)
	}
	if !strings.Contains(fc.bodies[0], `"id":"00000000000000ab"`) || !strings.Contains(fc.bodies[1], `"bytes":5`) {
		t.Fatalf("bodies = %v", fc.bodies)
	}
	fc.flushErr = errors.New("connection closed")
	if err := x.Export(context.Background(), []plugin.ExportRecord{{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{}}}); err == nil {
		t.Fatal("a flush error must reach the caller")
	}
	if err := x.Stop(context.Background()); err != nil || !fc.closed {
		t.Fatalf("stop: %v closed=%v", err, fc.closed)
	}
}

// A server that is down at startup must not stop Packeteer: the connect
// options retry in the background.
func TestStartDoesNotNeedAServer(t *testing.T) {
	x, err := build(t, "urls: [\"nats://127.0.0.1:1\"]\ntimeout: 200ms\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Start(context.Background()); err != nil {
		t.Fatalf("start with no server: %v", err)
	}
	if err := x.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}
