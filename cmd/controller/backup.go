package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Backup archive (#31): a gzip'd tar with manifest.json, config.yaml (the
// loaded file as it is on disk), and, when a storage plugin that supports
// it is configured, storage/history (its Backup output). Secrets are
// environment variables and are not in the config file, so none are in
// the archive.
const (
	backupFormat   = "packeteer-backup/v1"
	backupManifest = "manifest.json"
	backupConfig   = "config.yaml"
	backupHistory  = "storage/history"
	// maxBackupConfig caps the config entry read on restore.
	maxBackupConfig = 16 << 20
)

type manifest struct {
	Format  string    `json:"format"`
	Version string    `json:"version"`
	Created time.Time `json:"created"`
	// ConfigPath is where the config was read from.
	ConfigPath string `json:"config_path"`
	// Storage is the backed-up storage plugin, when there is one.
	Storage *manifestStorage `json:"storage,omitempty"`
}

type manifestStorage struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// buildStorage builds only the storage plugin of cfg. It is not started.
func buildStorage(cfg *config.Config, log *slog.Logger, getenv func(string) string) (plugin.StorageBackup, *manifestStorage, error) {
	if cfg.Storage == nil {
		return nil, nil, nil
	}
	sp := *cfg.Storage
	node := sp.Config
	env := plugin.Env{Name: sp.InstanceName(), Logger: log, Getenv: getenv}
	st, err := plugin.Storages.New(sp.Type, plugin.NewConfig(&node), env)
	if err != nil {
		return nil, nil, fmt.Errorf("storage (%s): %w", sp.InstanceName(), err)
	}
	b, ok := st.(plugin.StorageBackup)
	if !ok {
		return nil, nil, fmt.Errorf("storage type %s does not support backup", sp.Type)
	}
	return b, &manifestStorage{Name: sp.InstanceName(), Type: sp.Type}, nil
}

// runBackup writes the archive to out. It never overwrites a file. It
// opens no BGP session and sends no probe.
func runBackup(ctx context.Context, cfgPath string, cfg *config.Config, out string, getenv func(string) string, stdout, stderr io.Writer) int {
	log := newLogger(stderr, cfg.Log.Level, cfg.Log.Format)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "packeteer: backup: %v\n", err)
		return 1
	}
	st, ms, err := buildStorage(cfg, log, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "packeteer: backup: %v\n", err)
		return 1
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "packeteer: backup: %v (the archive is never overwritten)\n", err)
		return 1
	}
	err = writeBackup(ctx, f, cfgPath, raw, st, ms)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(out)
		fmt.Fprintf(stderr, "packeteer: backup: %v\n", err)
		return 1
	}
	what := "config"
	if ms != nil {
		what = "config and " + ms.Type + " history"
	}
	fmt.Fprintf(stdout, "backup: wrote %s (%s)\n", out, what)
	return 0
}

func writeBackup(ctx context.Context, w io.Writer, cfgPath string, cfgRaw []byte, st plugin.StorageBackup, ms *manifestStorage) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	now := time.Now().UTC()
	man, err := json.MarshalIndent(manifest{Format: backupFormat, Version: version, Created: now, ConfigPath: cfgPath, Storage: ms}, "", "  ")
	if err != nil {
		return err
	}
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: now, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := add(backupManifest, man); err != nil {
		return err
	}
	if err := add(backupConfig, cfgRaw); err != nil {
		return err
	}
	if st != nil {
		// The tar header needs the size first: spool the snapshot.
		tmp, err := os.CreateTemp("", "packeteer-history-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		if err := st.Backup(ctx, tmp); err != nil {
			return fmt.Errorf("history: %w", err)
		}
		size, err := tmp.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: backupHistory, Mode: 0o600, Size: size, ModTime: now, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := io.Copy(tw, tmp); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// runRestore reads an archive, validates its config, restores history into
// the archived config's storage, and writes the config to configOut when
// it is set. It never overwrites unless force is set. The controller that
// uses the storage must be stopped. It opens no BGP session.
func runRestore(ctx context.Context, archive, configOut string, force bool, getenv func(string) string, stdout, stderr io.Writer) int {
	if err := restore(ctx, archive, configOut, force, getenv, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "packeteer: restore: %v\n", err)
		return 1
	}
	return 0
}

func restore(ctx context.Context, archive, configOut string, force bool, getenv func(string) string, stdout, stderr io.Writer) error {
	if configOut != "" && !force {
		if _, err := os.Stat(configOut); err == nil {
			return fmt.Errorf("%s exists (use -force to replace it)", configOut)
		}
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s is not a Packeteer backup: %w", archive, err)
	}
	tr := tar.NewReader(gz)
	var man *manifest
	var cfgRaw []byte
	var cfg *config.Config
	restored := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: %w", archive, err)
		}
		switch h.Name {
		case backupManifest:
			var m manifest
			if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&m); err != nil {
				return fmt.Errorf("manifest: %w", err)
			}
			if m.Format != backupFormat {
				return fmt.Errorf("unsupported backup format %q (want %s)", m.Format, backupFormat)
			}
			man = &m
		case backupConfig:
			if man == nil {
				return errors.New("config before manifest")
			}
			cfgRaw, err = io.ReadAll(io.LimitReader(tr, maxBackupConfig+1))
			if err != nil {
				return err
			}
			if len(cfgRaw) > maxBackupConfig {
				return errors.New("config is too large")
			}
			cfg, err = loadConfigBytes(cfgRaw)
			if err != nil {
				return fmt.Errorf("archived config: %w", err)
			}
		case backupHistory:
			if cfg == nil {
				return errors.New("history before config")
			}
			log := newLogger(stderr, cfg.Log.Level, cfg.Log.Format)
			st, ms, err := buildStorage(cfg, log, getenv)
			if err != nil {
				return err
			}
			if st == nil {
				return errors.New("the archive has history but its config has no storage")
			}
			if man.Storage == nil || man.Storage.Type != ms.Type {
				return fmt.Errorf("history was written by storage type %v, config has %s", man.Storage, ms.Type)
			}
			if err := st.Restore(ctx, tr, force); err != nil {
				return fmt.Errorf("history: %w", err)
			}
			restored = true
			fmt.Fprintf(stdout, "restore: %s history restored\n", ms.Type)
		default:
			return fmt.Errorf("unexpected entry %q", h.Name)
		}
	}
	if man == nil || cfg == nil {
		return fmt.Errorf("%s has no manifest or config", archive)
	}
	if man.Storage != nil && !restored {
		return errors.New("the manifest lists history but the archive has none")
	}
	if configOut != "" {
		if err := writeFileAtomic(configOut, cfgRaw, 0o600); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		fmt.Fprintf(stdout, "restore: config written to %s\n", configOut)
	} else {
		fmt.Fprintln(stdout, "restore: config validated (not written; set -restore-config)")
	}
	fmt.Fprintf(stdout, "restore: ok (backup from %s, packeteer %s)\n", man.Created.Format(time.RFC3339), man.Version)
	return nil
}

// loadConfigBytes validates a config the way the daemon loads one.
func loadConfigBytes(raw []byte) (*config.Config, error) {
	dir, err := os.MkdirTemp("", "packeteer-restore-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		return nil, err
	}
	return config.Load(p)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".restore-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
