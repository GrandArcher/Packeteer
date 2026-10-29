// Package oop holds what the out-of-process plugin types ("exec" and
// "grpc") share: the config block that names a program, its validation,
// the environment the program gets, and the JSON shapes of the prober
// and source calls. Both types can only be a prober, a target source, or
// a notifier, never an announcer.
package oop

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Plugin types that run a program from the plugin dir.
const (
	ExecType = "exec"
	GRPCType = "grpc"
)

// RunsProgram reports whether a plugin type starts a program. The config
// editor never adds or changes such an entry (docs/ui.md).
func RunsProgram(typ string) bool { return typ == ExecType || typ == GRPCType }

// DefaultTimeout bounds a single plugin call.
const DefaultTimeout = 30 * time.Second

// Launch is the part of a config block that says which program to run and
// what it gets.
type Launch struct {
	// Command is an absolute path, or a path relative to the plugin dir.
	Command string        `yaml:"command"`
	Args    []string      `yaml:"args"`
	Timeout time.Duration `yaml:"timeout"`
	// Env is passed to the process; values may reference ${VAR} from
	// Packeteer's environment. The rest of Packeteer's environment is not
	// inherited (only PATH).
	Env map[string]string `yaml:"env"`
	// Config is forwarded verbatim to the plugin.
	Config any `yaml:"config"`
}

// Spec is a validated Launch.
type Spec struct {
	Path    string
	Args    []string
	Env     []string
	Timeout time.Duration
	Config  any
	// Gate is set for a notifier only.
	Gate *plugin.EventGate
}

// ResolveCommand maps a configured command to an executable path. Relative
// paths must stay inside dir.
func ResolveCommand(dir, cmd string) (string, error) {
	if cmd == "" {
		return "", errors.New("command is required")
	}
	if filepath.IsAbs(cmd) {
		return filepath.Clean(cmd), nil
	}
	clean := filepath.Clean(cmd)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("command %q escapes the plugin dir", cmd)
	}
	if dir == "" {
		return "", fmt.Errorf("command %q is relative but no plugin dir is set", cmd)
	}
	return filepath.Join(dir, clean), nil
}

// NewSpec validates l and the notifier filter f for a plugin of kind. The
// command must be an executable file now; nothing is run.
func NewSpec(kind plugin.Kind, e plugin.Env, l Launch, f plugin.EventFilter) (Spec, error) {
	path, err := ResolveCommand(e.PluginDir, l.Command)
	if err != nil {
		return Spec{}, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return Spec{}, fmt.Errorf("command: %w", err)
	}
	if st.IsDir() || st.Mode()&0o111 == 0 {
		return Spec{}, fmt.Errorf("command %s is not an executable file", path)
	}
	if l.Timeout < 0 {
		return Spec{}, fmt.Errorf("timeout %s must not be negative", l.Timeout)
	}
	if l.Timeout == 0 {
		l.Timeout = DefaultTimeout
	}
	var gate *plugin.EventGate
	if kind == plugin.KindNotifier {
		if gate, err = plugin.NewEventGate(f); err != nil {
			return Spec{}, err
		}
	} else if len(f.Events) > 0 || f.MinSeverity != "" || f.RateLimit != 0 || f.RateWindow != 0 {
		return Spec{}, errors.New("events, min_severity, rate_limit, and rate_window are only for notifiers")
	}
	getenv := e.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	path0 := getenv("PATH")
	if path0 == "" {
		path0 = "/usr/local/bin:/usr/bin:/bin"
	}
	env := []string{"PATH=" + path0, "PACKETEER_PLUGIN_KIND=" + string(kind)}
	for k, v := range l.Env {
		if k == "" || strings.ContainsAny(k, "=\x00") {
			return Spec{}, fmt.Errorf("env: invalid variable name %q", k)
		}
		env = append(env, k+"="+os.Expand(v, getenv))
	}
	return Spec{Path: path, Args: l.Args, Env: env, Timeout: l.Timeout, Config: l.Config, Gate: gate}, nil
}
