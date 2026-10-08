package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// tables are the ones a restored file must have. usage_samples (#127) is
// not in this list: a backup taken before that table existed still
// restores. VACUUM INTO copies the whole file, so a current backup
// includes the samples.
var tables = []string{"probe_daily", "improvements", "mitigations", "prefixes"}

// Backup writes a consistent copy of the database to w (#31). It uses
// VACUUM INTO, so it can run while a controller writes to the same file.
func (s *Store) Backup(ctx context.Context, w io.Writer) error {
	if _, err := os.Stat(s.path); err != nil {
		return fmt.Errorf("no history at %s: %w", s.path, err)
	}
	dir, err := os.MkdirTemp("", "packeteer-backup-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	snap := filepath.Join(dir, "history.db")
	db, err := sql.Open("sqlite", "file:"+s.path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", snap); err != nil {
		return fmt.Errorf("snapshot %s: %w", s.path, err)
	}
	f, err := os.Open(snap)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// Restore checks a copy Backup wrote and moves it into place (#31). The
// old file's WAL and shared-memory files are removed with it.
func (s *Store) Restore(ctx context.Context, r io.Reader, overwrite bool) error {
	if _, err := os.Stat(s.path); err == nil && !overwrite {
		return fmt.Errorf("history already exists at %s (stop the controller and use -force to replace it)", s.path)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("storage dir: %w", err)
	}
	f, err := os.CreateTemp(dir, ".restore-*.db")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := check(ctx, tmp); err != nil {
		return fmt.Errorf("backup is not a Packeteer history database: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(s.path + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	ok = true
	return nil
}

// check opens path and verifies its integrity and tables.
func check(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var res string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return errors.New("integrity check: " + res)
	}
	var missing []string
	for _, t := range tables {
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", t).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return errors.New("missing tables: " + strings.Join(missing, ", "))
	}
	return nil
}
