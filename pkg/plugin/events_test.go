package plugin

import (
	"strings"
	"testing"
	"time"
)

func TestEventCatalogIsConsistent(t *testing.T) {
	kinds, traps := map[string]bool{}, map[int]bool{}
	problems, resolvers := map[string]bool{}, map[string]bool{}
	for _, s := range EventCatalog() {
		if kinds[s.Kind] {
			t.Errorf("duplicate kind %s", s.Kind)
		}
		kinds[s.Kind] = true
		if s.TrapID <= 0 || traps[s.TrapID] {
			t.Errorf("%s: trap id %d is not unique and positive", s.Kind, s.TrapID)
		}
		traps[s.TrapID] = true
		if _, ok := SeverityRank(s.Severity); !ok {
			t.Errorf("%s: bad severity %q", s.Kind, s.Severity)
		}
		if s.Group == "" || !strings.Contains(s.Kind, ".") || s.Summary == "" {
			t.Errorf("%s: group, dotted kind, and summary are required", s.Kind)
		}
		if s.Resolves {
			resolvers[s.Group] = true
		} else if s.Severity != SeverityInfo {
			problems[s.Group] = true
		}
	}
	for g := range problems {
		if !resolvers[g] {
			t.Errorf("group %s has a problem kind but nothing resolves it", g)
		}
	}
	for _, k := range []string{EventImprovementAdded, EventProviderDown, EventBGPSessionDown, EventCommitExceeded, EventOutageAS} {
		if !kinds[k] {
			t.Errorf("catalog is missing %s", k)
		}
	}
}

func TestEventCatalogCopy(t *testing.T) {
	c := EventCatalog()
	c[0].Kind = "changed"
	if _, ok := LookupEvent("changed"); ok {
		t.Fatal("EventCatalog must return a copy")
	}
}

func TestNewEventAndDedupKey(t *testing.T) {
	now := time.Unix(100, 0)
	down := NewEvent(EventProviderDown, now, "down", map[string]string{"provider": "transit-a", "reason": "x"})
	up := NewEvent(EventProviderUp, now, "up", map[string]string{"provider": "transit-a"})
	if down.Severity != SeverityCritical || up.Severity != SeverityInfo || !down.Time.Equal(now) {
		t.Fatalf("severities %s %s", down.Severity, up.Severity)
	}
	if down.DedupKey() != up.DedupKey() || down.DedupKey() != "packeteer/provider/provider=transit-a" {
		t.Fatalf("dedup keys %q %q", down.DedupKey(), up.DedupKey())
	}
	if down.Resolves() || !up.Resolves() {
		t.Fatal("resolves flags")
	}
	as := NewEvent(EventOutageAS, now, "", map[string]string{"asn": "64500"})
	cl := NewEvent(EventOutageCleared, now, "", map[string]string{"asn": "64500"})
	if as.DedupKey() != cl.DedupKey() {
		t.Fatalf("outage keys %q %q", as.DedupKey(), cl.DedupKey())
	}
	if u := NewEvent("x.unknown", now, "", nil); u.Severity != SeverityInfo || u.DedupKey() != "packeteer/x.unknown" {
		t.Fatalf("unknown %+v %s", u, u.DedupKey())
	}
}

func TestEventGateValidation(t *testing.T) {
	bad := []struct {
		f    EventFilter
		want string
	}{
		{EventFilter{Events: []string{"provider.dwn"}}, "matches no event kind"},
		{EventFilter{Events: []string{""}}, "empty"},
		{EventFilter{Events: []string{"[x"}}, "bad pattern"},
		{EventFilter{MinSeverity: "loud"}, `min_severity "loud"`},
		{EventFilter{RateLimit: -1}, "rate_limit"},
		{EventFilter{RateLimit: 1, RateWindow: time.Millisecond}, "at least 1s"},
		{EventFilter{RateWindow: 48 * time.Hour}, "rate_window"},
	}
	for _, b := range bad {
		if _, err := NewEventGate(b.f); err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("%+v: err = %v, want %q", b.f, err, b.want)
		}
	}
	for _, p := range []string{"*", "improvement.*", "bgp.session_down"} {
		if _, err := NewEventGate(EventFilter{Events: []string{p}}); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestEventGateMatch(t *testing.T) {
	g, err := NewEventGate(EventFilter{Events: []string{"provider.*", "improvement.added"}, MinSeverity: SeverityCritical})
	if err != nil {
		t.Fatal(err)
	}
	ev := func(k string) Event { return NewEvent(k, time.Time{}, "", nil) }
	cases := map[string]bool{
		EventProviderDown:       true,
		EventProviderUp:         true, // resolves a critical problem
		EventImprovementAdded:   false,
		EventBGPSessionDown:     false, // not in events
		EventImprovementRemoved: false,
	}
	for k, want := range cases {
		if got := g.Match(ev(k)); got != want {
			t.Errorf("%s: match = %v, want %v", k, got, want)
		}
	}
	w, _ := NewEventGate(EventFilter{MinSeverity: SeverityWarning})
	if w.Match(ev(EventImprovementRemoved)) || !w.Match(ev(EventCommitCleared)) || !w.Match(ev(EventControllerStarted)) {
		t.Error("warning gate: resolvers of info-only groups must stay filtered")
	}
	var nilGate *EventGate
	if !nilGate.Match(ev(EventImprovementAdded)) {
		t.Error("nil gate must match")
	}
}

func TestEventGateRateLimit(t *testing.T) {
	g, err := NewEventGate(EventFilter{RateLimit: 2, RateWindow: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEvent(EventProviderDown, time.Time{}, "", nil)
	t0 := time.Unix(1000, 0)
	for i, want := range []bool{true, true, false, false} {
		if ok, _ := g.Allow(e, t0.Add(time.Duration(i)*time.Second)); ok != want {
			t.Fatalf("event %d: allow = %v", i, ok)
		}
	}
	ok, suppressed := g.Allow(e, t0.Add(time.Minute))
	if !ok || suppressed != 2 {
		t.Fatalf("new window: ok=%v suppressed=%d", ok, suppressed)
	}
	if ok, s := g.Allow(e, t0.Add(time.Minute+time.Second)); !ok || s != 0 {
		t.Fatalf("suppressed must reset: ok=%v s=%d", ok, s)
	}
	out := e.WithSuppressed(3)
	if out.Fields["suppressed"] != "3" || e.Fields != nil {
		t.Fatal("WithSuppressed must copy fields")
	}
	unlimited, _ := NewEventGate(EventFilter{})
	for i := 0; i < 1000; i++ {
		if ok, _ := unlimited.Allow(e, t0); !ok {
			t.Fatal("rate_limit 0 is unlimited")
		}
	}
}
