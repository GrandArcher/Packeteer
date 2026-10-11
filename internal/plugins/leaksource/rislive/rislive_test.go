package rislive

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func build(t *testing.T, yaml string, asn uint32) (plugin.LeakSource, error) {
	t.Helper()
	cfg, err := plugin.ConfigFromYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, plugin.Env{ASN: asn, Logger: slog.New(slog.DiscardHandler)})
}

func TestConfigValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml string
		asn  uint32
		want string
	}{
		"unknown key": {"{nope: 1}", 64500, "nope"},
		"bad scheme":  {"{url: 'ftp://ris.example.invalid/'}", 64500, "http or https"},
		"has query":   {"{url: 'https://ris.example.invalid/v1/stream/?format=sse'}", 64500, "leave the query out"},
		"no asn":      {"{}", 0, "local asn"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := build(t, tc.yaml, tc.asn)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := build(t, "{}", 64500); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
}

type collector struct {
	mu  sync.Mutex
	got []plugin.LeakSighting
}

func (c *collector) sink(s plugin.LeakSighting) { c.mu.Lock(); c.got = append(c.got, s); c.mu.Unlock() }
func (c *collector) n() int                     { c.mu.Lock(); defer c.mu.Unlock(); return len(c.got) }

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

const stream = `{"type":"ris_message","data":{"timestamp":1,"peer":"192.0.2.9","peer_asn":"64511","id":"x","host":"rrc00","type":"UPDATE","path":[64511,64500,[64496,64497]],"community":[[64500,666],[64511,1]],"announcements":[{"next_hop":"192.0.2.9","prefixes":["203.0.113.0/24","2001:db8::/32"]}],"withdrawals":["198.51.100.0/24"]}}
{"type":"ris_message","data":{"timestamp":2,"peer":"192.0.2.9","peer_asn":"64511","id":"y","host":"rrc00","type":"KEEPALIVE"}}
{"type":"ris_error","data":{"message":"bad subscription"}}
not json
{"type":"pong","data":null}
`

func TestStreamBecomesSightings(t *testing.T) {
	var header, query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header, query = r.Header.Get("X-RIS-Subscribe"), r.URL.RawQuery
		fmt.Fprint(w, stream)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	src, err := build(t, fmt.Sprintf("{url: %q, client: lab-test}", srv.URL+"/v1/stream/"), 64500)
	if err != nil {
		t.Fatal(err)
	}
	var col collector
	src.SetLeakSink(col.sink)
	if src.Healthy() {
		t.Fatal("healthy before start")
	}
	if err := src.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "two sightings", func() bool { return col.n() == 2 })
	if !src.Healthy() {
		t.Fatal("not healthy with the stream open")
	}
	if header != `{"path":64500,"require":"announcements","type":"UPDATE"}` {
		t.Fatalf("subscription %s", header)
	}
	if query != "client=lab-test&format=json" {
		t.Fatalf("query %s", query)
	}
	s := col.got[0]
	if s.Prefix != netip.MustParsePrefix("203.0.113.0/24") || s.OurExport || s.Seen != "rrc00/192.0.2.9" {
		t.Fatalf("sighting %+v", s)
	}
	if fmt.Sprint(s.ASPath) != "[64511 64500 64496 64497]" {
		t.Fatalf("path %v (AS_SET must be flattened)", s.ASPath)
	}
	if fmt.Sprint(s.Communities) != fmt.Sprint([]uint32{64500<<16 | 666, 64511<<16 | 1}) {
		t.Fatalf("communities %v", s.Communities)
	}
	if col.got[1].Prefix != netip.MustParsePrefix("2001:db8::/32") {
		t.Fatalf("second %+v", col.got[1])
	}
	stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := src.Stop(stop); err != nil {
		t.Fatal(err)
	}
	if src.Healthy() {
		t.Fatal("healthy after stop")
	}
}

func TestOutageIsUnhealthyThenRecovers(t *testing.T) {
	var mu sync.Mutex
	up := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ok := up
		mu.Unlock()
		if !ok {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, stream)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	src, err := build(t, fmt.Sprintf("{url: %q}", srv.URL), 64500)
	if err != nil {
		t.Fatal(err)
	}
	src.(*Source).retry = 20 * time.Millisecond
	var col collector
	src.SetLeakSink(col.sink)
	if err := src.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer src.Stop(context.Background())
	time.Sleep(100 * time.Millisecond)
	if src.Healthy() || col.n() != 0 {
		t.Fatal("a refused stream must be unhealthy and silent")
	}
	mu.Lock()
	up = true
	mu.Unlock()
	waitFor(t, "recovery", func() bool { return src.Healthy() && col.n() == 2 })
}

func TestStalledStreamIsUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	src, err := build(t, fmt.Sprintf("{url: %q}", srv.URL), 64500)
	if err != nil {
		t.Fatal(err)
	}
	s := src.(*Source)
	s.idle = 100 * time.Millisecond
	s.retry = time.Hour
	if err := src.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer src.Stop(context.Background())
	waitFor(t, "open stream reported healthy", src.Healthy)
	waitFor(t, "silent stream reported unhealthy", func() bool { return !src.Healthy() })
}
