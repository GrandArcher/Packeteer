package dirsync

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSync(t *testing.T) {
	dir := t.TempDir()
	if err := Sync(dir); err != nil {
		t.Fatalf("a writable directory: %v", err)
	}
	if err := Sync(filepath.Join(dir, "missing")); !errors.Is(err, ErrSync) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing directory: err = %v, want ErrSync wrapping ErrNotExist", err)
	}
	if os.Geteuid() == 0 {
		return
	}
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o300); err != nil {
		t.Fatal(err)
	}
	if err := Sync(locked); !errors.Is(err, ErrSync) || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("a directory that cannot be opened: err = %v, want ErrSync wrapping ErrPermission", err)
	}
}
