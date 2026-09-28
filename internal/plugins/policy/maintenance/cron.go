package maintenance

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// schedule is a five-field cron expression: minute, hour, day of month,
// month, day of week. Each field accepts *, a number, a range a-b, a step
// (*/n or a-b/n), or a comma list of those. Day of week is 0-7 (0 and 7 are
// Sunday). As in Vixie cron, when both day fields are restricted a time
// matches if either one does; a day field that starts with * (for example
// */2) counts as unrestricted, so the two fields are then AND-ed.
type schedule struct {
	minute, hour, dom, month, dow uint64
	domStar, dowStar              bool
}

func parseSchedule(s string) (schedule, error) {
	f := strings.Fields(s)
	if len(f) != 5 {
		return schedule{}, fmt.Errorf("schedule %q must have 5 fields (minute hour day-of-month month day-of-week)", s)
	}
	var sc schedule
	var err error
	if sc.minute, err = parseField(f[0], 0, 59); err != nil {
		return schedule{}, fmt.Errorf("schedule %q minute: %w", s, err)
	}
	if sc.hour, err = parseField(f[1], 0, 23); err != nil {
		return schedule{}, fmt.Errorf("schedule %q hour: %w", s, err)
	}
	if sc.dom, err = parseField(f[2], 1, 31); err != nil {
		return schedule{}, fmt.Errorf("schedule %q day of month: %w", s, err)
	}
	if sc.month, err = parseField(f[3], 1, 12); err != nil {
		return schedule{}, fmt.Errorf("schedule %q month: %w", s, err)
	}
	if sc.dow, err = parseField(f[4], 0, 7); err != nil {
		return schedule{}, fmt.Errorf("schedule %q day of week: %w", s, err)
	}
	if sc.dow&(1<<7) != 0 {
		sc.dow |= 1
	}
	sc.domStar = strings.HasPrefix(f[2], "*")
	sc.dowStar = strings.HasPrefix(f[4], "*")
	return sc, nil
}

func parseField(s string, lo, hi int) (uint64, error) {
	var bits uint64
	for _, part := range strings.Split(s, ",") {
		rng, stepStr, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepStr)
			if err != nil || n < 1 {
				return 0, fmt.Errorf("step %q must be a positive integer", stepStr)
			}
			step = n
		}
		a, b := lo, hi
		switch {
		case rng == "*":
		case strings.Contains(rng, "-"):
			x, y, _ := strings.Cut(rng, "-")
			var err1, err2 error
			a, err1 = strconv.Atoi(x)
			b, err2 = strconv.Atoi(y)
			if err1 != nil || err2 != nil {
				return 0, fmt.Errorf("range %q is invalid", rng)
			}
		default:
			n, err := strconv.Atoi(rng)
			if err != nil {
				return 0, fmt.Errorf("value %q is invalid", rng)
			}
			a, b = n, n
			if hasStep {
				b = hi
			}
		}
		if a < lo || b > hi || a > b {
			return 0, fmt.Errorf("%q is outside %d-%d", part, lo, hi)
		}
		for v := a; v <= b; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, nil
}

// matches reports whether the minute starting at t is a start time.
func (s schedule) matches(t time.Time) bool {
	if s.minute&(1<<uint(t.Minute())) == 0 || s.hour&(1<<uint(t.Hour())) == 0 || s.month&(1<<uint(t.Month())) == 0 {
		return false
	}
	return s.dayMatches(t)
}

func (s schedule) dayMatches(t time.Time) bool {
	domOK := s.dom&(1<<uint(t.Day())) != 0
	dowOK := s.dow&(1<<uint(t.Weekday())) != 0
	if s.domStar || s.dowStar {
		return domOK && dowOK
	}
	return domOK || dowOK
}

// lastStart returns the latest start time in (now-d, now], if any. Start
// times are whole minutes in loc. It skips whole months, days, and hours
// that cannot match, so a long duration costs at most a few thousand steps.
func (s schedule) lastStart(now time.Time, d time.Duration, loc *time.Location) (time.Time, bool) {
	t := now.In(loc).Truncate(time.Minute)
	for t.Add(d).After(now) {
		y, mo, day := t.Date()
		var next time.Time
		switch {
		case s.month&(1<<uint(mo)) == 0:
			next = time.Date(y, mo, 1, 0, 0, 0, 0, loc)
		case !s.dayMatches(t):
			next = time.Date(y, mo, day, 0, 0, 0, 0, loc)
		case s.hour&(1<<uint(t.Hour())) == 0:
			next = time.Date(y, mo, day, t.Hour(), 0, 0, 0, loc)
		default:
			if s.minute&(1<<uint(t.Minute())) != 0 {
				return t, true
			}
			next = t
		}
		// Step to the minute before the skipped span. time.Date may pick
		// the later instant of an ambiguous wall time; never step forward.
		next = next.Add(-time.Minute)
		if !next.Before(t) {
			next = t.Add(-time.Minute)
		}
		t = next
	}
	return time.Time{}, false
}
