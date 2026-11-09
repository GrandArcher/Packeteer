package sqlite

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestEvents covers the #173 table: append, filtered reads newest first,
// a restart on the same file, and prune by retention.
func TestEvents(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "p.db")
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	s := newStore(t, "path: "+path)
	s.now = func() time.Time { return now }
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	evs := []plugin.Event{
		{Time: now.Add(-500 * 24 * time.Hour), Kind: plugin.EventControllerStarted, Severity: plugin.SeverityInfo, Message: "too old"},
		{Time: now.Add(-3 * time.Hour), Kind: plugin.EventProviderDown, Severity: plugin.SeverityCritical, Message: "probe source for transit-a is down",
			Fields: map[string]string{"provider": "transit-a", "source": "192.0.2.10"}},
		{Time: now.Add(-2 * time.Hour), Kind: plugin.EventCommitExceeded, Severity: plugin.SeverityWarning, Message: "over commit",
			Fields: map[string]string{"provider": "transit-b"}},
		{Time: now.Add(-time.Hour), Kind: plugin.EventImprovementAdded, Severity: plugin.SeverityInfo, Message: "steered 198.51.100.0/24",
			Fields: map[string]string{"prefix": "198.51.100.0/24"}},
	}
	for _, e := range evs {
		if err := s.AppendEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Stop(ctx)

	s = newStore(t, "path: "+path)
	s.now = func() time.Time { return now }
	if err := s.Start(ctx); err != nil { // prunes the 500-day-old row
		t.Fatal(err)
	}
	defer s.Stop(ctx)

	kinds := func(q plugin.EventQuery) []string {
		t.Helper()
		got, err := s.Events(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range got {
			out = append(out, e.Kind)
		}
		return out
	}
	for name, tc := range map[string]struct {
		q    plugin.EventQuery
		want []string
	}{
		"all, newest first":    {plugin.EventQuery{}, []string{"improvement.added", "commit.exceeded", "provider.down"}},
		"warning and above":    {plugin.EventQuery{MinSeverity: plugin.SeverityWarning}, []string{"commit.exceeded", "provider.down"}},
		"critical only":        {plugin.EventQuery{MinSeverity: plugin.SeverityCritical}, []string{"provider.down"}},
		"text in a field":      {plugin.EventQuery{Text: "TRANSIT-B"}, []string{"commit.exceeded"}},
		"text in a message":    {plugin.EventQuery{Text: "198.51.100"}, []string{"improvement.added"}},
		"range":                {plugin.EventQuery{From: now.Add(-150 * time.Minute), To: now.Add(-90 * time.Minute)}, []string{"commit.exceeded"}},
		"limit keeps newest":   {plugin.EventQuery{Limit: 2}, []string{"improvement.added", "commit.exceeded"}},
		"limit after search":   {plugin.EventQuery{Text: "transit", Limit: 1}, []string{"commit.exceeded"}},
		"limit after severity": {plugin.EventQuery{MinSeverity: plugin.SeverityWarning, Limit: 1}, []string{"commit.exceeded"}},
		"no match":             {plugin.EventQuery{Text: "nothing like this"}, nil},
	} {
		if got := kinds(tc.q); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
	got, _ := s.Events(ctx, plugin.EventQuery{Text: "provider.down"})
	if len(got) != 1 || !reflect.DeepEqual(got[0], evs[1]) {
		t.Errorf("round trip: got %+v, want %+v", got, evs[1])
	}
}
