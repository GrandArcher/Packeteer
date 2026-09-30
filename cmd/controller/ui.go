package main

import (
	"io"
	"log/slog"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/subscribe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Remaining UI parity (#34): the config editor, custom dashboards, and
// report subscriptions. None of them announces.

// reportSenders maps notifier instance names to those that send reports,
// and lists every notifier name.
func reportSenders(plugins *pluginhost.Set) (map[string]plugin.ReportSender, []string) {
	senders := map[string]plugin.ReportSender{}
	var names []string
	for _, n := range plugins.Notifiers {
		names = append(names, n.Name)
		if rs, ok := n.Plugin.(plugin.ReportSender); ok {
			senders[n.Name] = rs
		}
	}
	return senders, names
}

// checkSubscriptions checks report_subscriptions against the report list
// and the notifiers that were built.
func checkSubscriptions(cfg *config.Config, plugins *pluginhost.Set) error {
	if len(cfg.ReportSubscriptions) == 0 {
		return nil
	}
	senders, names := reportSenders(plugins)
	return subscribe.Check(cfg.ReportSubscriptions, senders, names)
}

// newSubscriptions builds the scheduler, or nil when none are configured.
func newSubscriptions(cfg *config.Config, plugins *pluginhost.Set, src subscribe.Source, log *slog.Logger) (*subscribe.Scheduler, error) {
	if len(cfg.ReportSubscriptions) == 0 {
		return nil, nil
	}
	senders, _ := reportSenders(plugins)
	return subscribe.New(cfg.ReportSubscriptions, senders, src, log, time.Now)
}

// dashboardStore is the storage plugin's dashboard store, or nil.
func dashboardStore(plugins *pluginhost.Set) plugin.DashboardStore {
	if plugins == nil || plugins.Storage == nil {
		return nil
	}
	ds, _ := plugins.Storage.Plugin.(plugin.DashboardStore)
	return ds
}

// newConfigEditor returns the editor for the mounted file when
// http.config_editor is on. A candidate passes the same steps as a start:
// config.Parse, the runtime environment, and preflight (every plugin's
// config and the cross-checks). Nothing is started.
func newConfigEditor(cfg *config.Config, path string, getenv func(string) string, httpUser string) (*configedit.Editor, error) {
	if !cfg.HTTP.ConfigEditor {
		return nil, nil
	}
	check := func(data []byte) (*config.Config, error) {
		next, err := config.Parse(data)
		if err != nil {
			return nil, err
		}
		if err := applyRuntimeEnv(next, getenv); err != nil {
			return nil, err
		}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if _, err := preflight(next, quiet, getenv, httpUser); err != nil {
			return nil, err
		}
		return next, nil
	}
	diff := func(running, next *config.Config) ([]string, bool) {
		return restartKeys(running, next), !sameYAML(running.BGP.Neighbors, next.BGP.Neighbors)
	}
	return configedit.New(path, cfg, check, diff)
}
