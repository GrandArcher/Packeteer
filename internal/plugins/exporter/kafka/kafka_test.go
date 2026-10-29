package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func build(t *testing.T, y string) (plugin.Exporter, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"KUSER": "svc", "KPASS": "secret"}
	return plugin.Exporters.New(TypeName, c, plugin.Env{Name: "k", Getenv: func(k string) string { return env[k] }})
}

func TestConfigValidation(t *testing.T) {
	ok, err := build(t, "brokers: [kafka.example.net:9092]\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ok.Streams(), ","); got != "events,decisions" {
		t.Fatalf("default streams = %s, flows must be opt-in", got)
	}
	withFlows, err := build(t, "brokers: [kafka.example.net:9092]\nstreams: [flows]\n")
	if err != nil || strings.Join(withFlows.Streams(), ",") != "flows" {
		t.Fatalf("flows: %v %v", withFlows, err)
	}
	for name, y := range map[string]string{
		"no brokers":       "topic_prefix: x\n",
		"bad broker":       "brokers: [kafka.example.net]\n",
		"bad stream":       "brokers: [a:9092]\nstreams: [traces]\n",
		"dup stream":       "brokers: [a:9092]\nstreams: [events, events]\n",
		"bad topic prefix": "brokers: [a:9092]\ntopic_prefix: \"a b\"\n",
		"short timeout":    "brokers: [a:9092]\ntimeout: 500ms\n",
		"negative timeout": "brokers: [a:9092]\ntimeout: -1s\n",
		"unknown field":    "brokers: [a:9092]\nacks: all\n",
		"ca without tls":   "brokers: [a:9092]\nca_file: /x.pem\n",
		"sasl no creds":    "brokers: [a:9092]\ntls: true\nsasl: plain\n",
		"sasl no tls":      "brokers: [a:9092]\nsasl: plain\nusername_env: KUSER\npassword_env: KPASS\n",
		"creds no sasl":    "brokers: [a:9092]\nusername_env: KUSER\npassword_env: KPASS\n",
		"bad sasl":         "brokers: [a:9092]\ntls: true\nsasl: gssapi\nusername_env: KUSER\npassword_env: KPASS\n",
		"unset password":   "brokers: [a:9092]\ntls: true\nsasl: plain\nusername_env: KUSER\npassword_env: NOPE\n",
	} {
		if _, err := build(t, y); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	for _, mech := range []string{"plain", "scram-sha-256", "scram-sha-512"} {
		if _, err := build(t, "brokers: [a:9092]\ntls: true\nsasl: "+mech+"\nusername_env: KUSER\npassword_env: KPASS\n"); err != nil {
			t.Errorf("sasl %s: %v", mech, err)
		}
	}
}

type fakeProducer struct {
	recs   []*kgo.Record
	err    error
	closed bool
}

func (f *fakeProducer) ProduceSync(_ context.Context, rs ...*kgo.Record) kgo.ProduceResults {
	f.recs = append(f.recs, rs...)
	var out kgo.ProduceResults
	for _, r := range rs {
		out = append(out, kgo.ProduceResult{Record: r, Err: f.err})
	}
	return out
}
func (f *fakeProducer) Close() { f.closed = true }

func TestExportProducesJSONToTopicPerStream(t *testing.T) {
	x, err := build(t, "brokers: [a:9092]\ntopic_prefix: edge1\nstreams: [events, decisions, flows]\n")
	if err != nil {
		t.Fatal(err)
	}
	k := x.(*Exporter)
	fp := &fakeProducer{}
	k.dial = func(...kgo.Opt) (producer, error) { return fp, nil }
	if err := x.Export(context.Background(), nil); err == nil {
		t.Fatal("export before Start must fail")
	}
	if err := x.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	err = x.Export(context.Background(), []plugin.ExportRecord{
		{Stream: plugin.StreamEvents, Event: &plugin.Event{Time: at, Kind: "improvement.added"}},
		{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{Time: at, ID: "0123456789abcdef", Prefix: "192.0.2.0/24", Provider: "transit-b"}},
		{Stream: plugin.StreamFlows, Flow: &plugin.FlowRecord{Time: at, Prefix: "192.0.2.0/24", Bytes: 7, Provider: "transit-b", ImprovementID: "0123456789abcdef"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fp.recs) != 3 {
		t.Fatalf("produced %d records", len(fp.recs))
	}
	wantTopics := []string{"edge1.events", "edge1.decisions", "edge1.flows"}
	wantKeys := []string{"improvement.added", "192.0.2.0/24", "192.0.2.0/24"}
	for i, r := range fp.recs {
		if r.Topic != wantTopics[i] || string(r.Key) != wantKeys[i] || !r.Timestamp.Equal(at) {
			t.Errorf("record %d: topic %q key %q ts %v", i, r.Topic, r.Key, r.Timestamp)
		}
		var m map[string]any
		if err := json.Unmarshal(r.Value, &m); err != nil {
			t.Errorf("record %d is not JSON: %v", i, err)
		}
	}
	var flow plugin.FlowRecord
	if err := json.Unmarshal(fp.recs[2].Value, &flow); err != nil || flow.Provider != "transit-b" || flow.ImprovementID != "0123456789abcdef" || flow.Bytes != 7 {
		t.Fatalf("flow body = %s (%v)", fp.recs[2].Value, err)
	}

	fp.err = errors.New("broker unavailable")
	if err := x.Export(context.Background(), []plugin.ExportRecord{{Stream: plugin.StreamEvents, Event: &plugin.Event{Kind: "x"}}}); err == nil {
		t.Fatal("a broker error must reach the caller")
	}
	if err := x.Stop(context.Background()); err != nil || !fp.closed {
		t.Fatalf("stop: %v closed=%v", err, fp.closed)
	}
}

// A broker that is down at startup must not stop Packeteer; the export
// fails and is counted instead.
func TestDownBrokerFailsExportNotStart(t *testing.T) {
	x, err := build(t, "brokers: [\"127.0.0.1:1\"]\ntimeout: 1s\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Start(context.Background()); err != nil {
		t.Fatalf("start with no broker: %v", err)
	}
	defer x.Stop(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := x.Export(ctx, []plugin.ExportRecord{{Stream: plugin.StreamEvents, Event: &plugin.Event{Kind: "x"}}}); err == nil {
		t.Fatal("export to a dead broker must fail")
	}
}
