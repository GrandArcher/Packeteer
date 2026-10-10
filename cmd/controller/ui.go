package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	execplugin "github.com/GrandArcher/Packeteer/internal/plugins/exec"
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
// config and the cross-checks), with plugins built check-only: no exec
// plugin command runs. A candidate that adds or changes an exec plugin or
// plugin_dir is refused: which programs the controller runs is set by
// the mounted file only, not through the API. Nothing is started.
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
		if err := checkExecUnchanged(cfg, next); err != nil {
			return nil, err
		}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if _, err := preflight(next, quiet, getenv, httpUser, true); err != nil {
			return nil, err
		}
		return next, nil
	}
	diff := func(running, next *config.Config) ([]string, []string) {
		return classify(running, next)
	}
	return configedit.New(path, cfg, check, diff)
}

// checkExecUnchanged refuses a candidate whose exec plugins or plugin_dir
// differ from the running config. Removing an exec plugin is allowed.
func checkExecUnchanged(running, next *config.Config) error {
	var errs []error
	if next.PluginDir != running.PluginDir {
		errs = append(errs, errors.New("plugin_dir: cannot be changed through the config editor; edit the mounted file"))
	}
	have := execSpecs(running)
	for _, sp := range execSpecs(next) {
		i := slices.IndexFunc(have, func(h execSpec) bool { return h.field == sp.field && sameYAML(h.spec, sp.spec) })
		if i < 0 {
			errs = append(errs, fmt.Errorf("%s (%s): exec plugins cannot be added or changed through the config editor; edit the mounted file",
				sp.field, sp.spec.InstanceName()))
			continue
		}
		have = slices.Delete(have, i, i+1)
	}
	return errors.Join(errs...)
}

type execSpec struct {
	field string // yaml path without list indexes, e.g. "probers"
	spec  config.PluginSpec
}

// execSpecs lists every plugin spec of type exec anywhere in cfg.
func execSpecs(cfg *config.Config) []execSpec {
	var out []execSpec
	specType := reflect.TypeFor[config.PluginSpec]()
	var walk func(v reflect.Value, field string)
	walk = func(v reflect.Value, field string) {
		switch v.Kind() {
		case reflect.Pointer, reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem(), field)
			}
		case reflect.Slice, reflect.Array:
			for i := range v.Len() {
				walk(v.Index(i), field)
			}
		case reflect.Map:
			for _, k := range v.MapKeys() {
				walk(v.MapIndex(k), field)
			}
		case reflect.Struct:
			if v.Type() == specType {
				if sp := v.Interface().(config.PluginSpec); sp.Type == execplugin.TypeName {
					out = append(out, execSpec{field: field, spec: sp})
				}
				return
			}
			t := v.Type()
			for i := range t.NumField() {
				f := t.Field(i)
				if !f.IsExported() {
					continue
				}
				name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
				if name == "-" {
					continue
				}
				path := field
				if name != "" {
					path = strings.TrimPrefix(field+"."+name, ".")
				}
				walk(v.Field(i), path)
			}
		}
	}
	walk(reflect.ValueOf(cfg), "")
	return out
}

// setupInfo is what the dashboard's first-run checklist reads from the
// loaded config (#49): the target source types and the cap.
func setupInfo(cfg *config.Config, plugins *pluginhost.Set) httpapi.Setup {
	st := httpapi.Setup{}
	if cfg.MaxImprovements != nil {
		st.MaxImprovements = *cfg.MaxImprovements
	}
	for _, s := range plugins.SourcesSnapshot() {
		st.Sources = append(st.Sources, s.Type)
	}
	return st
}
