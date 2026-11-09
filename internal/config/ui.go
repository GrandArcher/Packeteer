package config

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

// Web UI features (#34): the config editor switch and scheduled email
// report subscriptions. Neither announces routes.

// Report subscription schedules.
const (
	ScheduleDaily   = "daily"
	ScheduleWeekly  = "weekly"
	ScheduleMonthly = "monthly"
)

// Report subscription defaults and bounds.
const (
	DefaultSubscriptionAt = "06:00"
	MaxSubscriptions      = 50
	MaxSubscriptionTo     = 50
	MaxSubscriptionDays   = 366
)

// ReportSubscription emails one stored report on a schedule (#34). The
// report is the same one /api/reports/<report> serves, attached as CSV.
// Times are UTC. Recipients come only from this file, never from the API.
type ReportSubscription struct {
	Name string `yaml:"name"`
	// Report is a report name from /api/reports (summary, improvements,
	// providers, ...). Checked against the list when the controller
	// starts and by the config editor.
	Report string `yaml:"report"`
	// Schedule is daily, weekly, or monthly.
	Schedule string `yaml:"schedule"`
	// At is the UTC time of day to send, HH:MM (default 06:00).
	At string `yaml:"at"`
	// Weekday is the day a weekly report goes out (default monday).
	Weekday string `yaml:"weekday"`
	// Days is the report range ending at the send time (default 1, 7, or
	// 30 by schedule; at most 366).
	Days int `yaml:"days"`
	// Notifier names the notifiers entry that sends it. It must be a
	// notifier that sends reports (smtp).
	Notifier string `yaml:"notifier"`
	// To overrides the notifier's recipients. Empty uses the notifier's.
	To []string `yaml:"to"`
}

var subscriptionName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Weekdays by config name.
var Weekdays = map[string]time.Weekday{
	"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday, "wednesday": time.Wednesday,
	"thursday": time.Thursday, "friday": time.Friday, "saturday": time.Saturday,
}

// ParseAt parses an HH:MM time of day into hours and minutes.
func ParseAt(s string) (h, m int, ok bool) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, 0, false
	}
	return t.Hour(), t.Minute(), true
}

func (c *Config) defaultSubscriptions() {
	for i := range c.ReportSubscriptions {
		s := &c.ReportSubscriptions[i]
		s.Schedule = strings.ToLower(strings.TrimSpace(s.Schedule))
		s.Weekday = strings.ToLower(strings.TrimSpace(s.Weekday))
		if s.At == "" {
			s.At = DefaultSubscriptionAt
		}
		if s.Schedule == ScheduleWeekly && s.Weekday == "" {
			s.Weekday = "monday"
		}
		if s.Days == 0 {
			switch s.Schedule {
			case ScheduleDaily:
				s.Days = 1
			case ScheduleWeekly:
				s.Days = 7
			case ScheduleMonthly:
				s.Days = 30
			}
		}
	}
}

func (c *Config) validateSubscriptions(add func(string, ...any)) {
	subs := c.ReportSubscriptions
	if len(subs) == 0 {
		return
	}
	if len(subs) > MaxSubscriptions {
		add("report_subscriptions: at most %d entries", MaxSubscriptions)
	}
	if c.Storage == nil {
		add("report_subscriptions need a storage plugin (reports come from stored history)")
	}
	notifiers := map[string]bool{}
	for _, n := range c.Notifiers {
		notifiers[n.InstanceName()] = true
	}
	seen := map[string]bool{}
	for i, s := range subs {
		where := fmt.Sprintf("report_subscriptions[%d]", i)
		if !subscriptionName.MatchString(s.Name) {
			add("%s: name %q must be 1-63 of a-z, 0-9, _ and -", where, s.Name)
		} else if seen[s.Name] {
			add("%s: name %q is used twice", where, s.Name)
		}
		seen[s.Name] = true
		if strings.TrimSpace(s.Report) == "" {
			add("%s: report is required (a name from /api/reports)", where)
		}
		switch s.Schedule {
		case ScheduleDaily, ScheduleMonthly:
			if s.Weekday != "" {
				add("%s: weekday is only for schedule weekly", where)
			}
		case ScheduleWeekly:
			if _, ok := Weekdays[s.Weekday]; !ok {
				add("%s: weekday %q is invalid (want monday ... sunday)", where, s.Weekday)
			}
		default:
			add("%s: schedule %q is invalid (want daily, weekly, or monthly)", where, s.Schedule)
		}
		if _, _, ok := ParseAt(s.At); !ok {
			add("%s: at %q must be HH:MM (UTC)", where, s.At)
		}
		if s.Days < 1 || s.Days > MaxSubscriptionDays {
			add("%s: days %d must be between 1 and %d", where, s.Days, MaxSubscriptionDays)
		}
		switch {
		case s.Notifier == "":
			add("%s: notifier is required (the name of a notifiers entry, type smtp)", where)
		case !notifiers[s.Notifier]:
			add("%s: notifier %q is not in notifiers", where, s.Notifier)
		}
		if len(s.To) > MaxSubscriptionTo {
			add("%s: to has more than %d addresses", where, MaxSubscriptionTo)
		}
		for j, t := range s.To {
			if _, err := mail.ParseAddress(t); err != nil {
				add("%s: to[%d] %q: %v", where, j, t, err)
			}
		}
	}
}
