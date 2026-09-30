// Package subscribe emails stored reports on a schedule (#34, IRP
// "Email report subscriptions"). Each subscription names a report from
// /api/reports, a daily, weekly, or monthly UTC schedule, and a notifier
// that implements plugin.ReportSender (smtp). It only reads history and
// sends mail: it never announces, never changes a decision, and a failed
// send is logged and retried at the next scheduled time. Sends missed
// while the controller was down are not replayed.
package subscribe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// SendTimeout bounds building and sending one report.
const SendTimeout = 2 * time.Minute

// ErrNotFound is an unknown subscription name.
var ErrNotFound = errors.New("no such report subscription")

// Source builds reports from stored history.
type Source interface {
	Report(ctx context.Context, q history.Query) (history.Report, error)
}

// Status is one subscription's state for the API.
type Status struct {
	Name      string    `json:"name"`
	Report    string    `json:"report"`
	Schedule  string    `json:"schedule"`
	At        string    `json:"at"`
	Weekday   string    `json:"weekday,omitempty"`
	Days      int       `json:"days"`
	Notifier  string    `json:"notifier"`
	To        int       `json:"to"` // recipients overriding the notifier's; 0 uses the notifier's
	Next      time.Time `json:"next"`
	LastSent  time.Time `json:"last_sent,omitzero"`
	LastError string    `json:"last_error,omitempty"`
	Sent      int       `json:"sent"`
	Failed    int       `json:"failed"`
}

type entry struct {
	sub    config.ReportSubscription
	sender plugin.ReportSender
	next   time.Time
	last   time.Time
	err    string
	sent   int
	failed int
}

// Scheduler runs the subscriptions.
type Scheduler struct {
	src  Source
	log  *slog.Logger
	now  func() time.Time
	mu   sync.Mutex
	subs []*entry
	send sync.Mutex // one send at a time
}

// Check validates subscriptions against the report list and the notifier
// set, as the controller does at start. senders maps notifier instance
// names to those that send reports; others lists every notifier name.
func Check(subs []config.ReportSubscription, senders map[string]plugin.ReportSender, others []string) error {
	var errs []error
	for i, s := range subs {
		if !history.Known(s.Report) {
			errs = append(errs, fmt.Errorf("report_subscriptions[%d]: report %q is unknown (see /api/reports)", i, s.Report))
		}
		if senders[s.Notifier] == nil {
			if slices.Contains(others, s.Notifier) {
				errs = append(errs, fmt.Errorf("report_subscriptions[%d]: notifier %q does not send reports (use type smtp)", i, s.Notifier))
			} else {
				errs = append(errs, fmt.Errorf("report_subscriptions[%d]: notifier %q is not in notifiers", i, s.Notifier))
			}
		}
	}
	return errors.Join(errs...)
}

// New builds a scheduler. Check must have passed.
func New(subs []config.ReportSubscription, senders map[string]plugin.ReportSender, src Source, log *slog.Logger, now func() time.Time) (*Scheduler, error) {
	if err := Check(subs, senders, nil); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, errors.New("report subscriptions need a storage plugin")
	}
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	s := &Scheduler{src: src, log: log, now: now}
	t := now().UTC()
	for _, sub := range subs {
		s.subs = append(s.subs, &entry{sub: sub, sender: senders[sub.Notifier], next: Next(sub, t)})
	}
	return s, nil
}

// Next is the first scheduled send strictly after t (UTC).
func Next(s config.ReportSubscription, t time.Time) time.Time {
	t = t.UTC()
	h, m, _ := config.ParseAt(s.At)
	day := time.Date(t.Year(), t.Month(), t.Day(), h, m, 0, 0, time.UTC)
	switch s.Schedule {
	case config.ScheduleWeekly:
		want := config.Weekdays[s.Weekday]
		day = day.AddDate(0, 0, (int(want)-int(day.Weekday())+7)%7)
		if !day.After(t) {
			day = day.AddDate(0, 0, 7)
		}
	case config.ScheduleMonthly:
		day = time.Date(t.Year(), t.Month(), 1, h, m, 0, 0, time.UTC)
		if !day.After(t) {
			day = day.AddDate(0, 1, 0)
		}
	default:
		if !day.After(t) {
			day = day.AddDate(0, 0, 1)
		}
	}
	return day
}

// Status lists every subscription.
func (s *Scheduler) Status() []Status {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Status, 0, len(s.subs))
	for _, e := range s.subs {
		out = append(out, Status{
			Name: e.sub.Name, Report: e.sub.Report, Schedule: e.sub.Schedule, At: e.sub.At, Weekday: e.sub.Weekday,
			Days: e.sub.Days, Notifier: e.sub.Notifier, To: len(e.sub.To), Next: e.next, LastSent: e.last,
			LastError: e.err, Sent: e.sent, Failed: e.failed,
		})
	}
	return out
}

// Run sends each subscription when it is due until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	if s == nil || len(s.subs) == 0 {
		return
	}
	for {
		wait := s.untilNext()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		s.RunDue(ctx)
	}
}

// untilNext is how long until the earliest send, at least a second and at
// most an hour (so a clock step is noticed).
func (s *Scheduler) untilNext() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	wait := time.Hour
	for _, e := range s.subs {
		if d := e.next.Sub(now); d < wait {
			wait = d
		}
	}
	return max(wait, time.Second)
}

// RunDue sends every subscription whose time has come and schedules its
// next send. It returns how many were attempted.
func (s *Scheduler) RunDue(ctx context.Context) int {
	now := s.now().UTC()
	s.mu.Lock()
	var due []*entry
	for _, e := range s.subs {
		if !e.next.After(now) {
			due = append(due, e)
		}
	}
	s.mu.Unlock()
	for _, e := range due {
		at := e.next
		err := s.deliver(ctx, e, at)
		s.mu.Lock()
		e.next = Next(e.sub, now)
		s.mu.Unlock()
		if err != nil {
			s.log.Warn("report subscription not sent; next try at the next scheduled time", "subscription", e.sub.Name, "err", err, "next", e.next)
		} else {
			s.log.Info("report subscription sent", "subscription", e.sub.Name, "report", e.sub.Report)
		}
	}
	return len(due)
}

// SendNow sends one subscription now, for the range ending now. The
// schedule does not change.
func (s *Scheduler) SendNow(ctx context.Context, name string) error {
	if s == nil {
		return ErrNotFound
	}
	s.mu.Lock()
	var e *entry
	for _, x := range s.subs {
		if x.sub.Name == name {
			e = x
		}
	}
	s.mu.Unlock()
	if e == nil {
		return ErrNotFound
	}
	return s.deliver(ctx, e, s.now().UTC())
}

func (s *Scheduler) deliver(ctx context.Context, e *entry, to time.Time) error {
	s.send.Lock()
	defer s.send.Unlock()
	ctx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	m, err := Build(ctx, s.src, e.sub, to)
	if err == nil {
		err = e.sender.SendReport(ctx, m)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		e.err, e.failed = err.Error(), e.failed+1
		return err
	}
	e.last, e.err, e.sent = s.now().UTC(), "", e.sent+1
	return nil
}

// Build renders one subscription's email for the range ending at to.
func Build(ctx context.Context, src Source, sub config.ReportSubscription, to time.Time) (plugin.ReportMail, error) {
	to = to.UTC()
	from := to.Add(-time.Duration(sub.Days) * 24 * time.Hour)
	rep, err := src.Report(ctx, history.Query{Name: sub.Report, From: from, To: to, Now: to})
	if err != nil {
		return plugin.ReportMail{}, fmt.Errorf("report %s: %w", sub.Report, err)
	}
	var csv bytes.Buffer
	if err := rep.CSV(&csv); err != nil {
		return plugin.ReportMail{}, fmt.Errorf("report %s csv: %w", sub.Report, err)
	}
	const stamp = "20060102T150405Z"
	var text bytes.Buffer
	fmt.Fprintf(&text, "Packeteer %s report (%s subscription %q).\n\n", sub.Report, sub.Schedule, sub.Name)
	fmt.Fprintf(&text, "Range: %s to %s UTC, %d day(s)\n", from.Format(time.RFC3339), to.Format(time.RFC3339), sub.Days)
	fmt.Fprintf(&text, "Rows: %d (CSV attached)\n\n", rep.Len())
	text.WriteString("The same report is on the dashboard and at /api/reports/" + sub.Report + ".\n")
	text.WriteString("Change or remove this subscription under report_subscriptions in the config file.\n")
	return plugin.ReportMail{
		Subscription: sub.Name, Report: sub.Report, To: sub.To,
		Subject:     fmt.Sprintf("%s report %s", sub.Report, to.Format(time.DateOnly)),
		Text:        text.String(),
		Attachments: []plugin.Attachment{{Name: fmt.Sprintf("packeteer-%s-%s-%s.csv", sub.Report, from.Format(stamp), to.Format(stamp)), ContentType: "text/csv", Data: csv.Bytes()}},
	}, nil
}
