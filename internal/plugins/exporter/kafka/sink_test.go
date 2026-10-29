//go:build sink

package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestSinkKafka produces to a real broker (CI starts Redpanda, see the
// exporters job) and reads the records back with a separate consumer.
func TestSinkKafka(t *testing.T) {
	broker := os.Getenv("PACKETEER_SINK_KAFKA")
	if broker == "" {
		t.Fatal("PACKETEER_SINK_KAFKA is not set")
	}
	prefix := fmt.Sprintf("sink%d", time.Now().UnixNano())
	x, err := build(t, fmt.Sprintf("brokers: [%q]\ntopic_prefix: %s\nstreams: [events, decisions, flows]\n", broker, prefix))
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer x.Stop(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	at := time.Now()
	batch := []plugin.ExportRecord{
		{Stream: plugin.StreamEvents, Event: &plugin.Event{Time: at, Kind: "improvement.added", Message: "m"}},
		{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{Time: at, ID: "00000000000000ab", Action: "improve", Prefix: "192.0.2.0/24", Provider: "transit-b"}},
		{Stream: plugin.StreamFlows, Flow: &plugin.FlowRecord{Time: at, Prefix: "192.0.2.0/24", Bytes: 1500, Provider: "transit-b", ImprovementID: "00000000000000ab"}},
	}
	// The first produce to a new topic can fail while the broker creates it.
	for {
		if err = x.Export(ctx, batch); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("export: %v", err)
		}
		time.Sleep(time.Second)
	}

	cl, err := kgo.NewClient(kgo.SeedBrokers(broker), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.ConsumeTopics(prefix+".events", prefix+".decisions", prefix+".flows"))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	got := map[string][]byte{}
	for len(got) < 3 {
		fetches := cl.PollFetches(ctx)
		if ctx.Err() != nil {
			t.Fatalf("read back %d of 3 topics: %v", len(got), ctx.Err())
		}
		fetches.EachRecord(func(r *kgo.Record) { got[r.Topic] = r.Value })
	}
	var flow plugin.FlowRecord
	if err := json.Unmarshal(got[prefix+".flows"], &flow); err != nil || flow.Provider != "transit-b" || flow.ImprovementID != "00000000000000ab" || flow.Bytes != 1500 {
		t.Fatalf("flow = %s (%v)", got[prefix+".flows"], err)
	}
	var dec plugin.DecisionRecord
	if err := json.Unmarshal(got[prefix+".decisions"], &dec); err != nil || dec.ID != "00000000000000ab" || dec.Provider != "transit-b" {
		t.Fatalf("decision = %s (%v)", got[prefix+".decisions"], err)
	}
}
