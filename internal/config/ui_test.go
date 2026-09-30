package config

import (
	"strings"
	"testing"
)

const subsBase = `
storage:
  type: sqlite
notifiers:
  - type: smtp
    name: mail
    config: {host: smtp.example.net, from: packeteer@example.net, to: [noc@example.net]}
`

func TestSubscriptionDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + subsBase + `
http:
  config_editor: true
report_subscriptions:
  - {name: daily, report: summary, schedule: daily, notifier: mail}
  - {name: weekly, report: providers, schedule: Weekly, notifier: mail, at: "07:30", to: [ops@example.net]}
  - {name: monthly, report: savings, schedule: monthly, notifier: mail, days: 31}
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HTTP.ConfigEditor {
		t.Fatal("config_editor not read")
	}
	s := cfg.ReportSubscriptions
	if s[0].At != DefaultSubscriptionAt || s[0].Days != 1 || s[0].Weekday != "" {
		t.Fatalf("daily = %+v", s[0])
	}
	if s[1].Schedule != ScheduleWeekly || s[1].Weekday != "monday" || s[1].Days != 7 || s[1].At != "07:30" {
		t.Fatalf("weekly = %+v", s[1])
	}
	if s[2].Days != 31 {
		t.Fatalf("monthly = %+v", s[2])
	}
}

func TestSubscriptionErrors(t *testing.T) {
	for _, tc := range []struct {
		base, sub, want string
	}{
		{"", "{name: a, report: summary, schedule: daily, notifier: mail}", "need a storage plugin"},
		{subsBase, "{name: A!, report: summary, schedule: daily, notifier: mail}", "name \"A!\""},
		{subsBase, "{name: a, schedule: daily, notifier: mail}", "report is required"},
		{subsBase, "{name: a, report: summary, schedule: hourly, notifier: mail}", "schedule \"hourly\""},
		{subsBase, "{name: a, report: summary, schedule: daily, weekday: monday, notifier: mail}", "weekday is only for schedule weekly"},
		{subsBase, "{name: a, report: summary, schedule: weekly, weekday: funday, notifier: mail}", "weekday \"funday\""},
		{subsBase, "{name: a, report: summary, schedule: daily, at: \"25:00\", notifier: mail}", "must be HH:MM"},
		{subsBase, "{name: a, report: summary, schedule: daily, days: 400, notifier: mail}", "days 400"},
		{subsBase, "{name: a, report: summary, schedule: daily}", "notifier is required"},
		{subsBase, "{name: a, report: summary, schedule: daily, notifier: pager}", "notifier \"pager\" is not in notifiers"},
		{subsBase, "{name: a, report: summary, schedule: daily, notifier: mail, to: [not-an-address]}", "to[0]"},
	} {
		_, err := Parse([]byte(validYAML + tc.base + "report_subscriptions:\n  - " + tc.sub + "\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.sub, err, tc.want)
		}
	}
	_, err := Parse([]byte(validYAML + subsBase + `report_subscriptions:
  - {name: a, report: summary, schedule: daily, notifier: mail}
  - {name: a, report: summary, schedule: daily, notifier: mail}
`))
	if err == nil || !strings.Contains(err.Error(), "used twice") {
		t.Errorf("duplicate: %v", err)
	}
}
