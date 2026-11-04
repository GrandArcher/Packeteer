// Package dirsync makes a rename durable by syncing the directory it
// happened in (#492).
package dirsync

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ErrSync marks a failed directory sync. The rename before it has
// happened, but a crash can still undo it.
var ErrSync = errors.New("directory sync failed")

// Sync fsyncs dir so a rename into it survives a crash. A filesystem that
// cannot sync a directory at all (EINVAL) is not an error: nothing more
// can be done on it.
func Sync(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSync, err)
	}
	serr := d.Sync()
	if errors.Is(serr, syscall.EINVAL) {
		serr = nil
	}
	if err := errors.Join(serr, d.Close()); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSync, dir, err)
	}
	return nil
}
