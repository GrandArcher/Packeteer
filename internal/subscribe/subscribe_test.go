package subscribe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeSource struct {
	mu      sync.Mutex
	queries []history.Query
	h       plugin.History
}

func (f *fakeSource) Report(_ context.Context, q history.Query) (history.Report, error) {
	f.mu.Lock()
	f.queries = append(f.queries, q)
	f.mu.Unlock()
	return history.Build(f.h, q)
}

type fakeSender struct {
	mu   sync.Mutex
	sent []plugin.ReportMail
	fail error
}

func (f *fakeSender) SendReport(_ context.Context, m plugin.ReportMail) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.sent = append(f.sent, m)
	return nil
}

func sub(name, schedule string) config.ReportSubscription {
	s := config.ReportSubscription{Name: name, Report: history.ReportSummary, Schedule: schedule, At: "06:00", Notifier: "mail", Days: 1}
	if schedule == config.ScheduleWeekly {
		s.Weekday, s.Days = "monday", 7
	}
	if schedule == config.ScheduleMonthly {
		s.Days = 30
	}
	return s
}

func TestNext(t *testing.T) {
	// 2026-09-30 is a Wednesday.
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, tc := range []struct {
		sched, now, want string
		weekday          string
	}{
		{config.ScheduleDaily, "2026-09-30T05:59:00Z", "2026-09-30T06:00:00Z", ""},
		{config.ScheduleDaily, "2026-09-30T06:00:00Z", "2026-10-01T06:00:00Z", ""},
		{config.ScheduleWeekly, "2026-09-30T12:00:00Z", "2026-10-05T06:00:00Z", "monday"},
		{config.ScheduleWeekly, "2026-09-30T05:00:00Z", "2026-09-30T06:00:00Z", "wednesday"},
		{config.ScheduleWeekly, "2026-09-30T06:00:00Z", "2026-10-07T06:00:00Z", "wednesday"},
		{config.ScheduleMonthly, "2026-09-30T12:00:00Z", "2026-10-01T06:00:00Z", ""},
		{config.ScheduleMonthly, "2026-12-01T06:00:00Z", "2027-01-01T06:00:00Z", ""},
		{config.ScheduleMonthly, "2026-10-01T05:00:00Z", "2026-10-01T06:00:00Z", ""},
		// A non-UTC clock is converted first.
		{config.ScheduleDaily, "2026-09-30T08:30:00+03:00", "2026-09-30T06:00:00Z", ""},
	} {
		s := sub("x", tc.sched)
		if tc.weekday != "" {
			s.Weekday = tc.weekday
		}
		if got := Next(s, at(tc.now)); !got.Equal(at(tc.want)) {
			t.Errorf("%s %s after %s: got %s want %s", tc.sched, tc.weekday, tc.now, got, tc.want)
		}
	}
}

func TestCheck(t *testing.T) {
	mail := &fakeSender{}
	s := sub("a", config.ScheduleDaily)
	if err := Check([]config.ReportSubscription{s}, map[string]plugin.ReportSender{"mail": mail}, []string{"mail"}); err != nil {
		t.Fatal(err)
	}
	bad := s
	bad.Report = "nope"
	if err := Check([]config.ReportSubscription{bad}, map[string]plugin.ReportSender{"mail": mail}, nil); err == nil || !strings.Contains(err.Error(), `report "nope" is unknown`) {
		t.Fatalf("unknown report: %v", err)
	}
	hook := s
	hook.Notifier = "hook"
	if err := Check([]config.ReportSubscription{hook}, map[string]plugin.ReportSender{"mail": mail}, []string{"mail", "hook"}); err == nil || !strings.Contains(err.Error(), "does not send reports") {
		t.Fatalf("webhook notifier: %v", err)
	}
}

func TestRunDueSendsAndReschedules(t *testing.T) {
	now := time.Date(2026, 9, 30, 5, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	src, mail := &fakeSource{}, &fakeSender{}
	d := sub("daily", config.ScheduleDaily)
	d.To = []string{"ops@example.net"}
	w := sub("weekly", config.ScheduleWeekly)
	s, err := New([]config.ReportSubscription{d, w}, map[string]plugin.ReportSender{"mail": mail}, src, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.RunDue(context.Background()); n != 0 || len(mail.sent) != 0 {
		t.Fatalf("sent before due: %d", n)
	}
	if got := s.untilNext(); got != time.Hour {
		t.Fatalf("until next = %s", got)
	}
	now = time.Date(2026, 9, 30, 6, 0, 30, 0, time.UTC)
	if n := s.RunDue(context.Background()); n != 1 {
		t.Fatalf("due = %d, want the daily one", n)
	}
	m := mail.sent[0]
	if m.Subscription != "daily" || m.Report != history.ReportSummary || len(m.To) != 1 || len(m.Attachments) != 1 ||
		len(m.Attachments[0].Data) == 0 || !strings.Contains(m.Text, "1 day(s)") || !strings.Contains(m.Subject, "2026-09-30") {
		t.Fatalf("mail = %+v", m)
	}
	q := src.queries[0]
	if !q.To.Equal(time.Date(2026, 9, 30, 6, 0, 0, 0, time.UTC)) || q.To.Sub(q.From) != 24*time.Hour {
		t.Fatalf("range = %s..%s (want the day ending at the scheduled time)", q.From, q.To)
	}
	st := s.Status()
	if st[0].Sent != 1 || !st[0].Next.Equal(time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)) || st[0].LastSent.IsZero() || st[0].To != 1 {
		t.Fatalf("status = %+v", st[0])
	}
	if st[1].Sent != 0 || !st[1].Next.Equal(time.Date(2026, 10, 5, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("weekly status = %+v", st[1])
	}
	// Running again in the same minute sends nothing twice.
	if n := s.RunDue(context.Background()); n != 0 {
		t.Fatalf("sent twice: %d", n)
	}
}

func TestFailedSendIsRecordedAndRetriedNextTime(t *testing.T) {
	now := time.Date(2026, 9, 30, 6, 0, 0, 0, time.UTC)
	mail := &fakeSender{fail: errors.New("relay down")}
	s, err := New([]config.ReportSubscription{sub("daily", config.ScheduleDaily)}, map[string]plugin.ReportSender{"mail": mail}, &fakeSource{},
		nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	s.RunDue(context.Background())
	st := s.Status()[0]
	if st.Failed != 1 || st.LastError != "relay down" || !st.Next.After(now) {
		t.Fatalf("status = %+v", st)
	}
	mail.fail = nil
	if err := s.SendNow(context.Background(), "daily"); err != nil {
		t.Fatal(err)
	}
	if st := s.Status()[0]; st.Sent != 1 || st.LastError != "" {
		t.Fatalf("after send now: %+v", st)
	}
	if err := s.SendNow(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestRunStopsWithContext(t *testing.T) {
	s, err := New([]config.ReportSubscription{sub("daily", config.ScheduleDaily)}, map[string]plugin.ReportSender{"mail": &fakeSender{}}, &fakeSource{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// FAB-31: a subscription report is not cut to the dashboard's default row
// limit, and the mail says so when the hard cap still cuts it.
func TestBuildCarriesEveryRowNotTheDefaultLimit(t *testing.T) {
	to := time.Date(2026, 9, 30, 6, 0, 0, 0, time.UTC)
	var h plugin.History
	for i := range 150 {
		h.Improvements = append(h.Improvements, plugin.ImprovementRecord{
			ID: fmt.Sprintf("imp-%d", i), Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32),
			Provider: "transit-b", Native: "transit-a", Start: to.Add(-time.Hour), Mode: "observe",
		})
	}
	s := sub("daily", config.ScheduleDaily)
	s.Report = history.ReportImprovements
	src := &fakeSource{h: h}
	m, err := Build(context.Background(), src, s, to)
	if err != nil {
		t.Fatal(err)
	}
	if src.queries[0].Limit != history.MaxLimit {
		t.Fatalf("query limit = %d, want %d", src.queries[0].Limit, history.MaxLimit)
	}
	if rows := strings.Count(string(m.Attachments[0].Data), "\n") - 1; rows != 150 {
		t.Fatalf("CSV rows = %d, want 150", rows)
	}
	if !strings.Contains(m.Text, "Rows: 150 (CSV attached)") {
		t.Fatalf("text = %q", m.Text)
	}
}

type cappedSource struct{}

func (cappedSource) Report(ctx context.Context, q history.Query) (history.Report, error) {
	q.Limit = 2
	var h plugin.History
	to := q.To
	for i := range 5 {
		h.Improvements = append(h.Improvements, plugin.ImprovementRecord{
			ID: fmt.Sprintf("imp-%d", i), Prefix: netip.MustParsePrefix("192.0.2.0/24"),
			Provider: "transit-b", Native: "transit-a", Start: to.Add(-time.Hour), Mode: "observe",
		})
	}
	return history.Build(h, q)
}

func TestBuildSaysWhenTheRowLimitCutTheReport(t *testing.T) {
	s := sub("daily", config.ScheduleDaily)
	s.Report = history.ReportImprovements
	m, err := Build(context.Background(), cappedSource{}, s, time.Date(2026, 9, 30, 6, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Text, "Rows: 2 of 5") {
		t.Fatalf("text = %q", m.Text)
	}
}
