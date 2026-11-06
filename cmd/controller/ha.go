package main

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// haLeader is the elector's Active, the Leader gate of the outbound,
// inbound, and mitigation controllers (#31). It is nil for a single
// instance, which is always active.
func haLeader(plugins *pluginhost.Set) func() bool {
	if plugins == nil || plugins.Elector == nil {
		return nil
	}
	return plugins.Elector.Plugin.Active
}

// haWithdrawSettle is how long an instance waits between withdrawing its
// routes and resigning. BGP does not acknowledge a withdraw; this keeps
// the UPDATE ahead of the other instance's first announcement. It is also
// the pause between withdraw tries on a step-down.
var haWithdrawSettle = time.Second

// haWithdrawTries is how many times a step-down tries the withdraw before
// it treats the failure as persistent and drops the BGP sessions.
const haWithdrawTries = 3

// haWithdrawTimeout bounds one withdraw try. Each try gets its own, so a
// slow first try does not leave the next ones without time (#528).
var haWithdrawTimeout = 3 * time.Second

// haStepDownBudget bounds all withdraw tries together, and separately the
// session drop and the resign. It is the same bound the tries shared
// before #528. A standby takes over at least ttl/2 after this instance
// steps down, so with a short ttl and a short edge hold time the other
// instance can announce before a hung withdraw or drop ends; the budget
// is not derived from the lease ttl.
var haStepDownBudget = 10 * time.Second

// haRIB is the RIB surface candidacy reads (*rib.View).
type haRIB interface {
	Ready() bool
	RouteHold(context.Context) time.Duration
}

// haControl connects the elector to the controller (#31). A nil
// *haControl is a single instance: always active. It never announces. On
// becoming standby it withdraws every Packeteer route at once, then
// resigns so the other instance can take over without waiting for the
// lease to run out. When the withdraw keeps failing it drops the BGP
// sessions instead (#492). The decision loop skips decisions while
// standby and drops the decision state when it sees the step-down.
type haControl struct {
	el           plugin.Elector
	typ          string
	log          *slog.Logger
	withdraw     func(context.Context) error
	dropSessions func(context.Context) error
	poke         func()
	emit         func(now time.Time, kind, msg string, fields map[string]string)

	mu  sync.Mutex
	was bool // active as last reported by an event
}

// newHAControl registers candidacy and the change handler on the elector.
// It must run before the plugins start. withdraw removes every Packeteer
// route (outbound, inbound, mitigation); dropSessions shuts the RIB
// speaker's sessions down for good (rib.View.DropSessions).
func newHAControl(plugins *pluginhost.Set, log *slog.Logger, view haRIB, withdraw, dropSessions func(context.Context) error,
	poke func(), emit func(time.Time, string, string, map[string]string)) *haControl {
	if plugins == nil || plugins.Elector == nil {
		return nil
	}
	h := &haControl{el: plugins.Elector.Plugin, typ: plugins.Elector.Type, log: log, withdraw: withdraw, dropSessions: dropSessions, poke: poke, emit: emit}
	h.el.SetCandidate(func() plugin.Candidacy {
		if view == nil {
			return plugin.Candidacy{}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return plugin.Candidacy{Eligible: view.Ready(), RouteHold: view.RouteHold(ctx)}
	})
	h.el.OnChange(h.changed)
	return h
}

// active reports whether this instance may decide and announce.
func (h *haControl) active() bool { return h == nil || h.el.Active() }

// status is the elector's view for /api/ha.
func (h *haControl) status() plugin.ElectorStatus {
	st := h.el.Status()
	st.Type = h.typ
	return st
}

// changed runs on the elector's goroutine after each role change.
func (h *haControl) changed() {
	if h.el.Active() {
		h.mu.Lock()
		was := h.was
		h.was = true
		h.mu.Unlock()
		if !was {
			st := h.status()
			h.log.Warn("ha: active; announcing from this instance", "id", st.ID, "detail", st.Detail)
			h.emit(time.Now(), plugin.EventHAActive, "packeteer "+st.ID+" is now the active instance",
				map[string]string{"id": st.ID, "detail": st.Detail, "takeovers": strconv.Itoa(st.Takeovers)})
		}
		h.poke()
		return
	}
	// Withdraw now, not at the next decision round: the other instance
	// may take over as soon as this one resigns.
	err := h.withdrawTries()
	h.mu.Lock()
	was := h.was
	h.was = false
	h.mu.Unlock()
	st := h.status()
	if was {
		h.log.Warn("ha: standby; Packeteer routes withdrawn", "id", st.ID, "holder", st.Holder, "detail", st.Detail, "withdraw_err", err)
		h.emit(time.Now(), plugin.EventHAStandby, "packeteer "+st.ID+" is now standby; its routes are withdrawn",
			map[string]string{"id": st.ID, "holder": st.Holder, "detail": st.Detail, "withdrawn": strconv.FormatBool(err == nil)})
	}
	h.poke()
	if err != nil && h.el.Active() {
		// The lease came back while the withdraw failed. This instance is
		// the holder again and its routes are its own. Dropping the
		// sessions now would leave the active instance without them until
		// a restart.
		h.log.Warn("ha: active again after a failed standby withdraw; keeping the BGP sessions", "err", err)
		return
	}
	if err != nil {
		// The other instance takes over once the lease runs out, on the
		// assumption that this one's routes are gone, which holds only
		// for a dead holder. Closing the sessions makes every router drop
		// them. Not resigning: the other instance still waits the route
		// hold time, the backstop if a session does not close.
		h.log.Error("ha: withdraw on standby failed; dropping the BGP sessions so the routers remove Packeteer routes, not resigning; restart this instance to bring it back",
			"err", err, "tries", haWithdrawTries)
		dctx, dcancel := context.WithTimeout(context.Background(), haStepDownBudget)
		defer dcancel()
		if derr := h.dropSessions(dctx); derr != nil {
			h.log.Error("ha: dropping the BGP sessions failed; the routers keep Packeteer routes until the hold timer expires", "err", derr)
		}
		return
	}
	if !was {
		// Never announced in this term, or shutdown already resigned.
		return
	}
	time.Sleep(haWithdrawSettle)
	ctx, cancel := context.WithTimeout(context.Background(), haStepDownBudget)
	defer cancel()
	if err := h.el.Resign(ctx); err != nil {
		h.log.Warn("ha: resign", "err", err)
	}
}

// withdrawTries runs the withdraw up to haWithdrawTries times,
// haWithdrawSettle apart, each with its own haWithdrawTimeout but all
// inside haStepDownBudget, and returns the last error.
func (h *haControl) withdrawTries() error {
	budget, cancel := context.WithTimeout(context.Background(), haStepDownBudget)
	defer cancel()
	var err error
	for i := range haWithdrawTries {
		if err = h.withdrawOnce(budget); err == nil {
			return nil
		}
		if i == haWithdrawTries-1 {
			break
		}
		h.log.Warn("ha: withdraw on standby failed; trying again", "err", err, "try", i+1)
		select {
		case <-time.After(haWithdrawSettle):
		case <-budget.Done():
			return errors.Join(err, budget.Err())
		}
	}
	return err
}

func (h *haControl) withdrawOnce(budget context.Context) error {
	ctx, cancel := context.WithTimeout(budget, haWithdrawTimeout)
	defer cancel()
	return h.withdraw(ctx)
}

// shutdown resigns after the shutdown withdraw, so the standby takes over
// at its next renewal. A failed withdraw leaves the lease to run out.
func (h *haControl) shutdown(ctx context.Context, withdrawErr error) {
	if h == nil {
		return
	}
	h.mu.Lock()
	was := h.was
	h.was = false
	h.mu.Unlock()
	if withdrawErr != nil {
		h.log.Error("ha: withdraw on shutdown failed; not resigning (the lease runs out)", "err", withdrawErr)
		return
	}
	h.log.Info("ha: shutting down; Packeteer routes withdrawn, releasing the lease")
	time.Sleep(haWithdrawSettle)
	if err := h.el.Resign(ctx); err != nil {
		h.log.Warn("ha: resign on shutdown", "err", err)
		return
	}
	if was {
		st := h.status()
		h.emit(time.Now(), plugin.EventHAStandby, "packeteer "+st.ID+" is shutting down; routes withdrawn and lease released",
			map[string]string{"id": st.ID, "detail": "shutdown", "withdrawn": "true"})
	}
}
