package main

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// maintenanceOpener is implemented by the maintenance policy.
type maintenanceOpener interface {
	plugin.Maintenance
	Windows(now time.Time) (upcoming, finished []plugin.MaintenanceWindow)
	Open(providers []string, start, end time.Time, reason string, now time.Time) (plugin.MaintenanceWindow, error)
	Close(id string) bool
}

// maintenanceControl lists windows from every maintenance policy and opens
// on-demand windows on the first one. A change wakes the decision loop so
// improvements move off the provider without waiting for a probe round.
// Each call reads the current policy list, so a policy replaced online is
// the one the API uses. The control stays nil when none existed at start:
// adding the first maintenance policy still needs a restart for this API.
// Decide sees a new chain on the next round either way.
type maintenanceControl struct {
	plugins *pluginhost.Set
	log     *slog.Logger
	poke    func()
}

func newMaintenanceControl(plugins *pluginhost.Set, log *slog.Logger, poke func()) httpapi.MaintenanceControl {
	if plugins == nil {
		return nil
	}
	found := false
	for _, pol := range plugins.PoliciesSnapshot() {
		if _, ok := pol.Plugin.(plugin.Maintenance); ok {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	return &maintenanceControl{plugins: plugins, log: log, poke: poke}
}

func (mc *maintenanceControl) policies() (all []plugin.Maintenance, opener maintenanceOpener) {
	if mc == nil || mc.plugins == nil {
		return nil, nil
	}
	for _, pol := range mc.plugins.PoliciesSnapshot() {
		if m, ok := pol.Plugin.(plugin.Maintenance); ok {
			all = append(all, m)
		}
		if o, ok := pol.Plugin.(maintenanceOpener); ok && opener == nil {
			opener = o
		}
	}
	return all, opener
}

func (mc *maintenanceControl) Active(now time.Time) []plugin.MaintenanceWindow {
	all, _ := mc.policies()
	var out []plugin.MaintenanceWindow
	for _, m := range all {
		out = append(out, m.Active(now)...)
	}
	return out
}

func (mc *maintenanceControl) Windows(now time.Time) (upcoming, finished []plugin.MaintenanceWindow) {
	if mc == nil || mc.plugins == nil {
		return nil, nil
	}
	for _, pol := range mc.plugins.PoliciesSnapshot() {
		if m, ok := pol.Plugin.(maintenanceOpener); ok {
			u, f := m.Windows(now)
			upcoming, finished = append(upcoming, u...), append(finished, f...)
		}
	}
	return upcoming, finished
}

func (mc *maintenanceControl) CanOpen() bool {
	_, opener := mc.policies()
	return opener != nil
}

func (mc *maintenanceControl) Open(providers []string, start, end time.Time, reason string, now time.Time) (plugin.MaintenanceWindow, error) {
	_, opener := mc.policies()
	if opener == nil {
		return plugin.MaintenanceWindow{}, errors.New("no maintenance policy configured")
	}
	w, err := opener.Open(providers, start, end, reason, now)
	if err != nil {
		return w, err
	}
	if mc.log != nil {
		mc.log.Info("maintenance window opened", "id", w.ID, "providers", strings.Join(w.Providers, ","), "end", w.End, "reason", w.Reason)
	}
	if mc.poke != nil {
		mc.poke()
	}
	return w, nil
}

func (mc *maintenanceControl) Close(id string) bool {
	_, opener := mc.policies()
	if opener == nil || !opener.Close(id) {
		return false
	}
	if mc.log != nil {
		mc.log.Info("maintenance window closed", "id", id)
	}
	if mc.poke != nil {
		mc.poke()
	}
	return true
}

// maintenanceWatchInterval is how often scheduled windows are checked.
const maintenanceWatchInterval = 15 * time.Second

// watchMaintenance wakes the decision loop when the set of providers in
// maintenance changes, so a scheduled window that opens or closes takes
// effect without waiting for the next probe round.
func watchMaintenance(ctx context.Context, active func(time.Time) []plugin.MaintenanceWindow, every time.Duration, log *slog.Logger, poke func()) {
	key := func(now time.Time) string {
		var names []string
		for _, w := range active(now) {
			names = append(names, w.Providers...)
		}
		slices.Sort(names)
		return strings.Join(slices.Compact(names), ",")
	}
	last := key(time.Now())
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if k := key(now); k != last {
				if log != nil {
					log.Info("providers in maintenance changed", "providers", k)
				}
				last = k
				poke()
			}
		}
	}
}
