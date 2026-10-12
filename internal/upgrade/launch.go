package upgrade

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// LaunchedEnv marks a process the launcher or an upgrade started from a
// staged binary. A marked process never hands over again, so a bad state
// cannot loop.
const LaunchedEnv = "PACKETEER_UPGRADE_LAUNCHED"

// Launched reports whether getenv says this process is a staged version.
func Launched(getenv func(string) string) bool { return getenv(LaunchedEnv) != "" }

// Target is the binary to start in place of this process.
type Target struct {
	Path    string
	Version string
	// Env is the environment to give it: the current one, with LaunchedEnv
	// set for a staged binary and cleared for the base.
	Env []string
}

// Relaunch is the launcher. It runs at start of the installed (base)
// binary, before anything else is started. It returns the staged binary
// to start instead, or ok false to keep running as this process.
//
// A staged binary that starts MaxAttempts times without confirming it
// stayed up is dropped: the state goes back to the previous version, and
// the reason is kept for the Settings page. A state made for a different
// base version (the image was updated) is discarded.
func Relaunch(dir, ownVersion, ownPath string, environ []string, log *slog.Logger, now time.Time) (Target, bool) {
	s := store{dir: dir}
	st, err := s.load()
	if err != nil {
		log.Warn("upgrade state unreadable; running the installed version", "err", err)
		return Target{}, false
	}
	if st == nil {
		return Target{}, false
	}
	if st.BaseVersion != ownVersion || st.BasePath != ownPath {
		log.Info("upgrade state is for another installed version; ignoring it", "state_base", st.BaseVersion, "running", ownVersion)
		_ = os.Remove(s.statePath())
		return Target{}, false
	}
	for range 3 {
		if st.Active.zero() || st.Active.Path == st.BasePath {
			return Target{}, false
		}
		reason := ""
		if sum, err := fileSHA256(st.Active.Path); err != nil || sum != st.Active.SHA256 {
			reason = fmt.Sprintf("staged %s is missing or does not match its recorded checksum", st.Active.Version)
		} else if !st.Confirmed && st.Attempts >= MaxAttempts {
			reason = fmt.Sprintf("%s did not stay up in %d starts", st.Active.Version, st.Attempts)
		}
		if reason == "" {
			st.Attempts++
			if err := s.save(st, now); err != nil {
				log.Warn("upgrade state not writable; running the installed version", "err", err)
				return Target{}, false
			}
			return Target{Path: st.Active.Path, Version: st.Active.Version, Env: withLaunched(environ, st.Active.Version)}, true
		}
		log.Error("upgrade: going back to the previous version", "reason", reason)
		st.LastError = reason
		revert(st)
		if err := s.save(st, now); err != nil {
			log.Warn("upgrade state not writable; running the installed version", "err", err)
			return Target{}, false
		}
	}
	return Target{}, false
}

// revert makes Previous (or the base) Active. Previous is then empty.
func revert(st *State) {
	if st.Previous.zero() {
		st.Active = Entry{Version: st.BaseVersion, Path: st.BasePath}
	} else {
		st.Active = st.Previous
	}
	st.Previous = Entry{}
	st.Attempts, st.Confirmed = 0, true
}

func withLaunched(environ []string, version string) []string {
	out := without(environ, LaunchedEnv)
	return append(out, LaunchedEnv+"="+Normalize(version))
}

func without(environ []string, key string) []string {
	out := make([]string, 0, len(environ)+1)
	for _, e := range environ {
		if !strings.HasPrefix(e, key+"=") {
			out = append(out, e)
		}
	}
	return out
}
