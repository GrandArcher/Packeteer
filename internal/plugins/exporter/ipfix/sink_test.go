//go:build sink

package ipfix

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestSinkIPFIX sends to a real collector (CI starts GoFlow2 with
// lab/exporters/goflow2-mapping.yaml, see the exporters job) and reads its
// JSON output: a third-party decoder must accept the templates and records
// and see the provider tag and improvement ID.
func TestSinkIPFIX(t *testing.T) {
	addr, file := os.Getenv("PACKETEER_SINK_IPFIX"), os.Getenv("PACKETEER_SINK_IPFIX_FILE")
	if addr == "" || file == "" {
		t.Fatal("PACKETEER_SINK_IPFIX and PACKETEER_SINK_IPFIX_FILE must be set")
	}
	x, err := build(t, "address: "+addr+"\nobservation_domain: 42\ntemplate_interval: 1s\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer x.Stop(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// UDP: send until the collector has the templates and writes a record.
	for {
		if err := x.Export(ctx, []plugin.ExportRecord{
			flow("192.0.2.10", 1500, "transit-b", "00000000000000ab"),
			flow("2001:db8::5", 900, "transit-a", ""),
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		b, _ := os.ReadFile(file)
		s := string(b)
		if strings.Contains(s, `"dst_addr":"192.0.2.10"`) && strings.Contains(s, `"bytes":1500`) &&
			strings.Contains(s, `"src_addr":"203.0.113.9"`) && strings.Contains(s, `"provider":"transit-b"`) &&
			strings.Contains(s, `"improvement_id":171`) && strings.Contains(s, `"dst_addr":"2001:db8::5"`) {
			return
		}
		if ctx.Err() != nil {
			t.Fatalf("the collector never decoded the flows; file has:\n%s", s)
		}
	}
}
