package main

import (
	"context"
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
// the UPDATE ahead of the other instance's first announcement.
var haWithdrawSettle = time.Second

// haRIB is the RIB surface candidacy reads (*rib.View).
type haRIB interface {
	Ready() bool
	RouteHold(context.Context) time.Duration
}

// haControl connects the elector to the controller (#31). A nil
// *haControl is a single instance: always active. It never announces. On
// becoming standby it withdraws every Packeteer route at once, then
// resigns so the other instance can take over without waiting for the
// lease to run out. The decision loop skips decisions while standby and
// drops the decision state when it sees the step-down.
type haControl struct {
	el       plugin.Elector
	typ      string
	log      *slog.Logger
	withdraw func(context.Context) error
	poke     func()
	emit     func(now time.Time, kind, msg string, fields map[string]string)

	mu  sync.Mutex
	was bool // active as last reported by an event
}

// newHAControl registers candidacy and the change handler on the elector.
// It must run before the plugins start. withdraw removes every Packeteer
// route (outbound, inbound, mitigation).
func newHAControl(plugins *pluginhost.Set, log *slog.Logger, view haRIB, withdraw func(context.Context) error,
	poke func(), emit func(time.Time, string, string, map[string]string)) *haControl {
	if plugins == nil || plugins.Elector == nil {
		return nil
	}
	h := &haControl{el: plugins.Elector.Plugin, typ: plugins.Elector.Type, log: log, withdraw: withdraw, poke: poke, emit: emit}
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := h.withdraw(ctx)
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
	if err != nil {
		// Not resigning: the lease runs out, and the other instance waits
		// the route hold time before it announces.
		h.log.Error("ha: withdraw on standby failed; not resigning", "err", err)
		return
	}
	if !was {
		// Never announced in this term, or shutdown already resigned.
		return
	}
	time.Sleep(haWithdrawSettle)
	if err := h.el.Resign(ctx); err != nil {
		h.log.Warn("ha: resign", "err", err)
	}
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
