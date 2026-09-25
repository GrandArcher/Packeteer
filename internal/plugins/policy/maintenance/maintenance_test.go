package maintenance

import (
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var providers = []string{"transit-a", "transit-b"}

func build(t *testing.T, yaml string) (*Policy, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(c, plugin.Env{Providers: providers})
	if err != nil {
		return nil, err
	}
	return p.(*Policy), nil
}

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func activeProviders(p *Policy, now time.Time) string {
	var out []string
	for _, w := range p.Active(now) {
		out = append(out, w.ID+"="+strings.Join(w.Providers, "+"))
	}
	return strings.Join(out, ",")
}

func TestScheduleAndOneOff(t *testing.T) {
	p, err := build(t, `
windows:
  - name: sat-night
    providers: [transit-b]
    schedule: "0 2 * * 6"
    duration: 2h
  - name: fiber-move
    providers: [transit-a]
    start: 2026-10-01T02:00:00Z
    end: 2026-10-01T04:00:00Z
`)
	if err != nil {
		t.Fatal(err)
	}
	// 2026-09-26 is a Saturday.
	tests := []struct {
		now  string
		want string
	}{
		{"2026-09-26T01:59:59Z", ""},
		{"2026-09-26T02:00:00Z", "schedule-sat-night=transit-b"},
		{"2026-09-26T03:59:59Z", "schedule-sat-night=transit-b"},
		{"2026-09-26T04:00:00Z", ""},
		{"2026-09-27T02:30:00Z", ""}, // Sunday
		{"2026-10-01T01:59:00Z", ""},
		{"2026-10-01T02:00:00Z", "schedule-fiber-move=transit-a"},
		{"2026-10-01T04:00:00Z", ""},
	}
	for _, tt := range tests {
		if got := activeProviders(p, ts(tt.now)); got != tt.want {
			t.Errorf("%s: active = %q, want %q", tt.now, got, tt.want)
		}
	}
	w := p.Active(ts("2026-09-26T03:00:00Z"))[0]
	if !w.Start.Equal(ts("2026-09-26T02:00:00Z")) || !w.End.Equal(ts("2026-09-26T04:00:00Z")) || w.Source != "schedule" {
		t.Fatalf("window = %+v", w)
	}
}

func TestTimezone(t *testing.T) {
	p, err := build(t, `
timezone: Europe/Amsterdam
windows: [{name: w, providers: [transit-a], schedule: "0 2 * * *", duration: 1h}]
`)
	if err != nil {
		t.Fatal(err)
	}
	// 02:00 in Amsterdam (CEST, UTC+2) is 00:00 UTC.
	if got := activeProviders(p, ts("2026-09-26T00:30:00Z")); got != "schedule-w=transit-a" {
		t.Fatalf("active = %q", got)
	}
	if got := activeProviders(p, ts("2026-09-26T02:30:00Z")); got != "" {
		t.Fatalf("active = %q", got)
	}
}

func TestOnDemand(t *testing.T) {
	p, err := build(t, `max_api_duration: 2h`)
	if err != nil {
		t.Fatal(err)
	}
	now := ts("2026-09-25T12:00:00Z")
	w, err := p.Open([]string{"transit-a"}, time.Hour, "provider ticket", now)
	if err != nil {
		t.Fatal(err)
	}
	if w.ID != "api-1" || w.Source != "api" || !w.End.Equal(now.Add(time.Hour)) {
		t.Fatalf("window = %+v", w)
	}
	if got := activeProviders(p, now.Add(30*time.Minute)); got != "api-1=transit-a" {
		t.Fatalf("active = %q", got)
	}
	if got := activeProviders(p, now.Add(time.Hour)); got != "" {
		t.Fatalf("expired window still active: %q", got)
	}
	w2, _ := p.Open([]string{"transit-b"}, time.Hour, "", now)
	if !p.Close(w2.ID) || p.Close(w2.ID) || p.Close("schedule-x") {
		t.Fatal("Close")
	}
	if got := activeProviders(p, now); got != "" {
		t.Fatalf("closed window still active: %q", got)
	}
	for _, tt := range []struct {
		prov []string
		d    time.Duration
		want string
	}{
		{nil, time.Hour, "at least one provider"},
		{[]string{"transit-z"}, time.Hour, "not configured"},
		{[]string{"transit-a"}, 3 * time.Hour, "must be between"},
		{[]string{"transit-a"}, time.Second, "must be between"},
	} {
		if _, err := p.Open(tt.prov, tt.d, "", now); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("Open(%v, %s) err = %v, want %q", tt.prov, tt.d, err, tt.want)
		}
	}
}

func TestOnDemandCap(t *testing.T) {
	p, _ := build(t, ``)
	now := ts("2026-09-25T12:00:00Z")
	for i := 0; i < MaxAPIWindows; i++ {
		if _, err := p.Open([]string{"transit-a"}, time.Hour, "", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Open([]string{"transit-a"}, time.Hour, "", now); err == nil {
		t.Fatal("cap not enforced")
	}
}

func TestMatchNever(t *testing.T) {
	p, _ := build(t, ``)
	if _, ok := p.Match(plugin.PolicySubject{}); ok {
		t.Fatal("maintenance matched a prefix")
	}
	var _ plugin.Maintenance = p
}

func TestValidation(t *testing.T) {
	tests := []struct{ yaml, want string }{
		{`windows: [{providers: [transit-a]}]`, "set schedule and duration, or start and end"},
		{`windows: [{providers: [transit-a], schedule: "0 2 * * *"}]`, "duration"},
		{`windows: [{providers: [transit-a], schedule: "0 2 * * *", duration: 8d}]`, "cannot unmarshal"},
		{`windows: [{providers: [transit-a], schedule: "0 2 * * *", duration: 200h}]`, "must be between"},
		{`windows: [{providers: [transit-a], schedule: "0 2 * *", duration: 1h}]`, "5 fields"},
		{`windows: [{providers: [transit-a], schedule: "61 2 * * *", duration: 1h}]`, "outside 0-59"},
		{`windows: [{providers: [transit-a], schedule: "*/0 2 * * *", duration: 1h}]`, "positive integer"},
		{`windows: [{providers: [transit-a], schedule: "0 2 * * *", duration: 1h, start: "2026-01-01T00:00:00Z"}]`, "not both"},
		{`windows: [{providers: [transit-a], start: "2026-01-01T00:00:00Z", end: "2025-01-01T00:00:00Z"}]`, "end must be after start"},
		{`windows: [{providers: [transit-a], start: "tomorrow", end: "2026-01-01T00:00:00Z"}]`, "RFC 3339"},
		{`windows: [{providers: [transit-z], schedule: "0 2 * * *", duration: 1h}]`, `provider "transit-z" is not configured`},
		{`windows: [{schedule: "0 2 * * *", duration: 1h}]`, "at least one provider"},
		{`windows: [{name: a, providers: [transit-a], schedule: "0 2 * * *", duration: 1h}, {name: a, providers: [transit-a], schedule: "0 3 * * *", duration: 1h}]`, "duplicate window name"},
		{`timezone: Mars/Olympus`, "timezone"},
		{`max_api_duration: 30s`, "max_api_duration"},
		{`bogus: 1`, "field bogus not found"},
	}
	for _, tt := range tests {
		if _, err := build(t, tt.yaml); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.yaml, err, tt.want)
		}
	}
}

func TestCron(t *testing.T) {
	tests := []struct {
		expr string
		at   string
		want bool
	}{
		{"*/15 * * * *", "2026-09-25T10:45:00Z", true},
		{"*/15 * * * *", "2026-09-25T10:46:00Z", false},
		{"0 1-3 * * *", "2026-09-25T03:00:00Z", true},
		{"0 1-3 * * *", "2026-09-25T04:00:00Z", false},
		{"0 0 1,15 * *", "2026-09-15T00:00:00Z", true},
		{"0 0 * * 7", "2026-09-27T00:00:00Z", true}, // Sunday as 7
		{"0 0 * * 0", "2026-09-27T00:00:00Z", true},
		{"0 0 * 10 *", "2026-09-27T00:00:00Z", false},
		// Both day fields restricted: either matches.
		{"0 0 1 * 5", "2026-09-25T00:00:00Z", true}, // Friday
		{"0 0 1 * 5", "2026-10-01T00:00:00Z", true}, // the 1st
		{"0 0 1 * 5", "2026-09-26T00:00:00Z", false},
		{"0 0 */2 * *", "2026-09-03T00:00:00Z", true},
		{"0 0 */2 * *", "2026-09-04T00:00:00Z", false},
		{"5/20 * * * *", "2026-09-25T00:25:00Z", true},
		// A day field starting with * is unrestricted, as in Vixie cron:
		// the two day fields are AND-ed.
		{"0 0 */2 * 1", "2026-09-07T00:00:00Z", true},  // Monday the 7th (*/2 is odd days)
		{"0 0 */2 * 1", "2026-09-14T00:00:00Z", false}, // Monday, but the 14th is even
		{"0 0 */2 * 1", "2026-09-03T00:00:00Z", false}, // the 3rd, a Thursday
		{"0 0 1 * */2", "2026-09-01T00:00:00Z", true},  // Tuesday the 1st
		{"0 0 1 * */2", "2026-07-01T00:00:00Z", false}, // Wednesday the 1st
	}
	for _, tt := range tests {
		s, err := parseSchedule(tt.expr)
		if err != nil {
			t.Fatalf("%s: %v", tt.expr, err)
		}
		if got := s.matches(ts(tt.at)); got != tt.want {
			t.Errorf("%s at %s = %v, want %v", tt.expr, tt.at, got, tt.want)
		}
	}
}

// lastStart skips months, days, and hours; it must agree with a
// minute-by-minute walk, including across DST changes.
func TestLastStartMatchesBruteForce(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	brute := func(s schedule, now time.Time, d time.Duration, loc *time.Location) (time.Time, bool) {
		for m := now.In(loc).Truncate(time.Minute); m.Add(d).After(now); m = m.Add(-time.Minute) {
			if s.matches(m) {
				return m, true
			}
		}
		return time.Time{}, false
	}
	exprs := []string{"* * * * *", "0 2 * * *", "30 1 * * 0", "59 23 31 12 *", "0 0 29 2 *",
		"15 */3 1,15 * *", "0 0 */2 * 1", "0 12 1 * 5", "45 1 * 3,11 *", "0 3 * 1 1-5"}
	nows := []string{"2026-03-08T07:30:00Z", "2026-11-01T06:10:00Z", "2026-12-31T23:59:30Z",
		"2027-01-01T00:00:00Z", "2026-09-25T10:17:00Z", "2028-03-01T00:30:00Z"}
	for _, e := range exprs {
		s, err := parseSchedule(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range nows {
			for _, loc := range []*time.Location{time.UTC, ny} {
				for _, d := range []time.Duration{time.Minute, 90 * time.Minute, 26 * time.Hour, MaxDuration} {
					now := ts(n)
					got, gok := s.lastStart(now, d, loc)
					want, wok := brute(s, now, d, loc)
					if gok != wok || !got.Equal(want) {
						t.Errorf("%q now=%s loc=%s d=%s: got %v %v, want %v %v", e, n, loc, d, got, gok, want, wok)
					}
				}
			}
		}
	}
}

func BenchmarkLastStartRare(b *testing.B) {
	s, err := parseSchedule("59 23 31 12 *")
	if err != nil {
		b.Fatal(err)
	}
	now := ts("2026-09-25T10:17:00Z")
	for b.Loop() {
		s.lastStart(now, MaxDuration, time.UTC)
	}
}
