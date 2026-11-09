//go:build !unix

package lease

import (
	"context"
	"errors"
)

// withLock needs flock; the container image is Linux.
func withLock(context.Context, string, func() error) error {
	return errors.New("lease: file locking is not supported on this system")
}
