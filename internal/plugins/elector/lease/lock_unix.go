//go:build unix

package lease

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

// withLock runs fn while holding an exclusive flock on path. It retries a
// non-blocking lock until ctx is done, so a stuck holder cannot hang the
// caller.
func withLock(ctx context.Context, path string, fn func() error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("lease lock: timed out waiting for the other instance")
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}
