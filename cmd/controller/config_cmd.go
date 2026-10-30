package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// inventoryTimeout bounds one read of the inventory.
const inventoryTimeout = 2 * time.Minute

// inventoryPlan is one read of the inventory merged into the config file.
type inventoryPlan struct {
	log     *slog.Logger
	cfg     *config.Config
	current []byte
	plan    configedit.InventoryPlan
}

// planInventory reads the config at path, reads the inventory it names, and
// plans the change. It writes nothing.
func planInventory(ctx context.Context, path string, getenv func(string) string, stderr io.Writer) (inventoryPlan, error) {
	current, err := os.ReadFile(path)
	if err != nil {
		return inventoryPlan{}, err
	}
	cfg, err := config.Parse(current)
	if err != nil {
		return inventoryPlan{}, fmt.Errorf("%s: %w", path, err)
	}
	// The same start-up defaults as the daemon, so the audit record lands in
	// the storage the controller keeps its audit log in.
	if err := startConfig(cfg, getenv); err != nil {
		return inventoryPlan{}, err
	}
	log := newLogger(stderr, cfg.Log.Level, cfg.Log.Format)
	if cfg.Inventory == nil {
		return inventoryPlan{}, errors.New("the config has no inventory block (inventory: {type: netbox, config: {...}})")
	}
	inv, err := pluginhost.BuildInventory(cfg, pluginhost.Options{Logger: log, Getenv: getenv})
	if err != nil {
		return inventoryPlan{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, inventoryTimeout)
	defer cancel()
	res, err := inv.Fetch(ctx)
	if err != nil {
		return inventoryPlan{}, fmt.Errorf("inventory %s: %w", cfg.Inventory.InstanceName(), err)
	}
	plan, err := configedit.PlanInventory(current, res)
	if err != nil {
		return inventoryPlan{}, err
	}
	return inventoryPlan{log: log, cfg: cfg, current: current, plan: plan}, nil
}

// runConfig is `packeteer config plan|diff|apply`. plan and diff only read:
// the inventory over GET and the config file. apply writes the config file
// the plan showed, and nothing else. Providers are restart-only, so a running
// controller keeps its providers until it restarts.
func runConfig(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	const usage = "usage: packeteer config plan|diff|apply [-config FILE] (apply: -plan ID [-git])"
	if len(args) == 0 || (args[0] != "plan" && args[0] != "diff" && args[0] != "apply") {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("config "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	defaultPath := DefaultConfigPath
	if p := getenv(ConfigEnv); p != "" {
		defaultPath = p
	}
	path := fs.String("config", defaultPath, "path to the YAML config file (env "+ConfigEnv+")")
	var planID *string
	var useGit *bool
	if sub == "apply" {
		planID = fs.String("plan", "", "the plan id printed by `config plan`; apply refuses if the inventory or the file changed since")
		useGit = fs.Bool("git", false, "commit the change in the git repository that holds the config file (the file must be tracked and clean)")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "packeteer: config %s: %v\n", sub, err)
		return 1
	}
	ip, err := planInventory(ctx, *path, getenv, stderr)
	if err != nil {
		return fail(err)
	}
	switch sub {
	case "plan":
		ip.plan.Format(stdout)
		return 0
	case "diff":
		if !ip.plan.Changed() {
			fmt.Fprintln(stdout, "the config already matches the inventory")
			return 0
		}
		fmt.Fprint(stdout, ip.plan.Diff)
		return 0
	}
	if *planID == "" {
		return fail(errors.New("apply needs -plan ID: run `packeteer config plan` and review it first"))
	}
	if !ip.plan.Changed() {
		fmt.Fprintln(stdout, "nothing to apply: the config already matches the inventory")
		return 0
	}
	if ip.plan.ID != *planID {
		return fail(fmt.Errorf("the plan is now %s, not %s: the inventory or the file changed; run plan again", ip.plan.ID, *planID))
	}
	if err := applyInventory(ctx, *path, ip, *useGit, getenv, stdout); err != nil {
		return fail(err)
	}
	return 0
}

// applyInventory writes the planned file. The audit store is opened before
// the write, so a storage that cannot be opened stops the apply; a record
// that then fails to write is logged, as for the ops API. With git, a failed
// commit restores the old file.
func applyInventory(ctx context.Context, path string, ip inventoryPlan, useGit bool, getenv func(string) string, stdout io.Writer) error {
	auditor, closeAudit, err := openCLIAuditor(ctx, ip.cfg, ip.log, getenv)
	if err != nil {
		return err
	}
	defer closeAudit()
	if useGit {
		if err := gitRequireClean(ctx, path); err != nil {
			return err
		}
	}
	if now, err := os.ReadFile(path); err != nil || !bytes.Equal(now, ip.current) {
		return errors.New("the config file changed while the plan was made; run plan again")
	}
	if err := configedit.WriteFile(path, ip.plan.YAML, ip.current); err != nil {
		return err
	}
	detail := "inventory " + ip.cfg.Inventory.Type + " plan " + ip.plan.ID + ": " + planSummary(ip.plan)
	if useGit {
		commit, err := gitCommit(ctx, path, "Apply inventory plan "+ip.plan.ID+"\n\n"+planText(ip.plan))
		if err != nil {
			_, _ = git(ctx, path, "reset", "--quiet", "--", filepath.Base(path))
			if rerr := configedit.WriteFile(path, ip.current, ip.plan.YAML); rerr != nil {
				return fmt.Errorf("%w (and the old file could not be restored: %v)", err, rerr)
			}
			return err
		}
		detail += " git " + commit
	}
	who := "cli"
	if u, err := user.Current(); err == nil && u.Username != "" {
		who = u.Username
	}
	auditor.Record(ctx, plugin.AuditRecord{Actor: who, Method: "system", Action: "CLI config apply", Target: filepath.Base(path), Detail: detail})
	ip.plan.Format(stdout)
	fmt.Fprintf(stdout, "applied plan %s to %s\n", ip.plan.ID, path)
	if !useGit {
		fmt.Fprintln(stdout, "not committed: add -git to record the change in the repository that holds the config")
	}
	fmt.Fprintln(stdout, "a running controller needs a restart to use changed providers (SIGHUP refuses them)")
	return nil
}

func planText(p configedit.InventoryPlan) string {
	var b bytes.Buffer
	p.Format(&b)
	return b.String()
}

// planSummary is the plan on one line for the audit log.
func planSummary(p configedit.InventoryPlan) string {
	parts := make([]string, 0, len(p.Changes))
	for _, c := range p.Changes {
		keys := make([]string, 0, len(c.Fields))
		for _, f := range c.Fields {
			keys = append(keys, f.Field)
		}
		parts = append(parts, c.Sign()+c.Name+"("+strings.Join(keys, ",")+")")
	}
	return strings.Join(parts, " ")
}

// openCLIAuditor returns an auditor that writes to the config's storage
// plugin when it keeps the audit log, and only to the log otherwise.
func openCLIAuditor(ctx context.Context, cfg *config.Config, log *slog.Logger, getenv func(string) string) (*auth.Auditor, func(), error) {
	none := func() {}
	if cfg.Storage == nil {
		return auth.NewAuditor(nil, nil, log), none, nil
	}
	sp := *cfg.Storage
	node := sp.Config
	st, err := plugin.Storages.New(sp.Type, plugin.NewConfig(&node), plugin.Env{Name: sp.InstanceName(), Logger: log, Getenv: getenv})
	if err != nil {
		return nil, nil, fmt.Errorf("storage (%s): %w", sp.InstanceName(), err)
	}
	as, ok := st.(plugin.AuditStore)
	if !ok {
		return auth.NewAuditor(nil, nil, log), none, nil
	}
	if err := st.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("storage (%s): %w", sp.InstanceName(), err)
	}
	return auth.NewAuditor(as, nil, log), func() { _ = st.Stop(context.Background()) }, nil
}

// git runs git in the directory of the config file. safe.directory lets it
// work on a mounted repository owned by another user.
func git(ctx context.Context, path string, args ...string) (string, error) {
	dir := filepath.Dir(path)
	full := append([]string{"-C", dir, "-c", "safe.directory=" + dir, "-c", "user.name=Packeteer", "-c", "user.email=packeteer@localhost"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// gitRequireClean refuses unless the file is tracked and has no uncommitted
// change, so the commit holds the inventory change and nothing else.
func gitRequireClean(ctx context.Context, path string) error {
	base := filepath.Base(path)
	if _, err := git(ctx, path, "ls-files", "--error-unmatch", "--", base); err != nil {
		return fmt.Errorf("-git needs the config file tracked in a git repository: %w", err)
	}
	status, err := git(ctx, path, "status", "--porcelain", "--", base)
	if err != nil {
		return err
	}
	if status != "" {
		return errors.New("-git needs the config file committed first: it has uncommitted changes")
	}
	return nil
}

// gitCommit commits the config file alone and returns the short hash.
func gitCommit(ctx context.Context, path, message string) (string, error) {
	base := filepath.Base(path)
	if _, err := git(ctx, path, "add", "--", base); err != nil {
		return "", err
	}
	if _, err := git(ctx, path, "commit", "-m", message, "--", base); err != nil {
		return "", err
	}
	return git(ctx, path, "rev-parse", "--short", "HEAD")
}
