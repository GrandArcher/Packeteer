package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// quarantineEvent is the catalog event for a quarantine starting or
// ending (#228).
func quarantineEvent(now time.Time, c policy.QuarantineChange) plugin.Event {
	q := c.Quarantine
	fields := map[string]string{
		"prefix": q.Prefix.String(), "reason": c.Reason, "flips": strconv.Itoa(q.Flips),
		"strikes": strconv.Itoa(q.Strikes), "until": q.Until.UTC().Format(time.RFC3339),
	}
	if c.Action == policy.QuarantineStart {
		return plugin.NewEvent(plugin.EventFlapQuarantined, now, fmt.Sprintf("%s parked on its native path: %s", q.Prefix, c.Reason), fields)
	}
	return plugin.NewEvent(plugin.EventFlapReleased, now, fmt.Sprintf("%s released from flap quarantine (%s)", q.Prefix, c.Reason), fields)
}

// quarantineControl is the API's handle on the flap quarantine. Releasing
// wakes the decision loop so the prefix is decided again at once.
type quarantineControl struct {
	decider *policy.Engine
	out     emitter
	poke    func()
	now     func() time.Time
}

func (c quarantineControl) Release(p netip.Prefix) bool {
	now := c.now()
	q, ok := c.decider.Release(p, now)
	if !ok {
		return false
	}
	c.out.Emit(quarantineEvent(now, policy.QuarantineChange{Action: policy.QuarantineRelease, Reason: "operator release", Quarantine: q}))
	c.poke()
	return true
}

func logQuarantines(log *slog.Logger, changes []policy.QuarantineChange) {
	for _, c := range changes {
		q := c.Quarantine
		msg := "flap quarantine released"
		if c.Action == policy.QuarantineStart {
			msg = "flap quarantine started"
		}
		log.Info(msg, "prefix", q.Prefix, "flips", q.Flips, "strikes", q.Strikes, "until", q.Until, "reason", c.Reason)
	}
}

// auditQuarantines records automatic quarantine changes in the audit log
// as the system actor. It writes off the decision loop so a slow store
// never delays a decision or a withdraw.
func auditQuarantines(audit *auth.Auditor, changes []policy.QuarantineChange) {
	if audit == nil || len(changes) == 0 {
		return
	}
	go func() {
		for _, c := range changes {
			audit.Record(context.Background(), plugin.AuditRecord{
				Actor: "system", Method: auth.MethodSystem, Action: "flap." + c.Action,
				Target: c.Quarantine.Prefix.String(), Detail: c.Reason,
			})
		}
	}()
}
