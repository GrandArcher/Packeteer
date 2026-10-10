package main

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/upgrade"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Upgrade from the UI (#196). The manager prepares a switch while the
// controller runs; the switch itself happens here, after the daemon has
// shut down through the SIGTERM path. Nothing in this file announces.

// Swapped in by tests: a real exec replaces the test process.
var (
	execFn       = syscall.Exec
	environFn    = os.Environ
	executableFn = os.Executable
)

// trialFn runs a staged binary's start checks. Nil uses the binary's
// -version and -check; tests set it because their binary is not Packeteer.
var trialFn func(ctx context.Context, path, version string) error

// confirmAfter is how long a staged version must stay up before it is
// recorded as good. Before that, a version that keeps failing to start is
// dropped for the previous one (upgrade.MaxAttempts).
var confirmAfter = 30 * time.Second

// upgradeRun carries the manager out of daemon, so run can start the new
// binary once the daemon has stopped.
type upgradeRun struct {
	mgr *upgrade.Manager
}

// launchStaged is the launcher at start: when the state names a staged
// version for this installed binary, start it in place of this process.
// It runs only for the daemon, never for -check, and never in a process
// that is already a staged version.
func launchStaged(cfg *config.Config, args []string, getenv func(string) string, log *slog.Logger) (code int, switched bool) {
	if !cfg.UpgradeEnabled() || upgrade.Launched(getenv) {
		return 0, false
	}
	exe, err := executableFn()
	if err != nil {
		return 0, false
	}
	tg, ok := upgrade.Relaunch(cfg.Upgrade.Dir, version, exe, environFn(), log, time.Now())
	if !ok {
		return 0, false
	}
	return execInto(tg, args, log)
}

// execInto replaces this process with the target, the same arguments. It
// returns only if that failed (switched false: keep running as this
// version) or, under a test, when the stub returns.
func execInto(tg upgrade.Target, args []string, log *slog.Logger) (code int, switched bool) {
	log.Info("starting another Packeteer version", "version", tg.Version, "path", tg.Path)
	if err := execFn(tg.Path, append([]string{tg.Path}, args...), tg.Env); err != nil {
		log.Error("could not start that version", "version", tg.Version, "err", err)
		return 1, false
	}
	return 0, true
}

// newUpgrade builds the manager, or nil when upgrade is off.
func newUpgrade(cfg *config.Config, path string, stop func(), ha func() plugin.ElectorStatus, audit *auth.Auditor, getenv func(string) string, log *slog.Logger) (*upgrade.Manager, error) {
	if !cfg.UpgradeEnabled() {
		return nil, nil
	}
	exe, _ := executableFn()
	return upgrade.New(upgrade.Options{
		Config: *cfg.Upgrade, Version: version, ConfigPath: path, Exe: exe, Environ: environFn(),
		HA: ha, Stop: stop, Log: log, Trial: trialFn,
		Audit: func(action, detail string, err error) {
			rec := plugin.AuditRecord{Actor: "system", Method: "system", Action: action, Target: "releases", Result: auth.ResultOK, Detail: detail}
			if err != nil {
				rec.Result, rec.Detail = auth.ResultFailed, detail+": "+err.Error()
			}
			audit.Record(context.Background(), rec)
		},
	}, upgrade.Launched(getenv))
}

// confirmUpgrade records a staged version as good once it has stayed up.
func confirmUpgrade(ctx context.Context, mgr *upgrade.Manager, getenv func(string) string) {
	if mgr == nil || !upgrade.Launched(getenv) {
		return
	}
	go func() {
		t := time.NewTimer(confirmAfter)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C:
			mgr.Confirm()
		}
	}()
}

// finishUpgrade starts the prepared version after a clean shutdown. A
// shutdown that failed undoes the switch: the state goes back to what ran.
func finishUpgrade(up *upgradeRun, code int, args []string, log *slog.Logger) (int, bool) {
	if up == nil || up.mgr == nil {
		return code, false
	}
	tg, ok := up.mgr.Pending()
	if !ok {
		return code, false
	}
	if code != 0 {
		log.Error("shutdown for the upgrade did not finish cleanly; staying on the current version")
		up.mgr.Abort("shutdown for the switch ended with exit code " + strconv.Itoa(code))
		return code, false
	}
	return execInto(tg, args, log)
}
