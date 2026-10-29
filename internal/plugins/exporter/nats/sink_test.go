//go:build sink

package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestSinkNATS publishes to a real server (CI starts nats-server, see the
// exporters job) and reads the messages back with a subscriber.
func TestSinkNATS(t *testing.T) {
	url := os.Getenv("PACKETEER_SINK_NATS")
	if url == "" {
		t.Fatal("PACKETEER_SINK_NATS is not set")
	}
	prefix := fmt.Sprintf("sink%d", time.Now().UnixNano())
	sub, err := natsgo.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	msgs := make(chan *natsgo.Msg, 8)
	if _, err := sub.ChanSubscribe(prefix+".>", msgs); err != nil {
		t.Fatal(err)
	}
	if err := sub.Flush(); err != nil {
		t.Fatal(err)
	}

	x, err := build(t, fmt.Sprintf("urls: [%q]\nsubject_prefix: %s\nstreams: [events, decisions, flows]\n", url, prefix))
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer x.Stop(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	at := time.Now()
	if err := x.Export(ctx, []plugin.ExportRecord{
		{Stream: plugin.StreamEvents, Event: &plugin.Event{Time: at, Kind: "improvement.added"}},
		{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{Time: at, ID: "00000000000000ab", Prefix: "192.0.2.0/24", Provider: "transit-b"}},
		{Stream: plugin.StreamFlows, Flow: &plugin.FlowRecord{Time: at, Prefix: "192.0.2.0/24", Bytes: 1500, Provider: "transit-b", ImprovementID: "00000000000000ab"}},
	}); err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	for len(got) < 3 {
		select {
		case m := <-msgs:
			got[m.Subject] = m.Data
		case <-ctx.Done():
			t.Fatalf("received %d of 3 subjects", len(got))
		}
	}
	var flow plugin.FlowRecord
	if err := json.Unmarshal(got[prefix+".flows"], &flow); err != nil || flow.Provider != "transit-b" || flow.ImprovementID != "00000000000000ab" {
		t.Fatalf("flow = %s (%v)", got[prefix+".flows"], err)
	}
}
