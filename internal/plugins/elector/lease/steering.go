package lease

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The operator steering state (#565) is a file beside the lease, on the
// volume both instances mount, so the instance that takes over restores
// what the active one saved.

var _ plugin.SteeringStore = (*Lease)(nil)

// maxSteeringBytes bounds a read; the core's document is far smaller.
const maxSteeringBytes = 4 << 20

func (l *Lease) steeringPath() string { return l.path + ".steering" }

// SteeringState returns the saved document, or nil.
func (l *Lease) SteeringState(context.Context) ([]byte, error) {
	f, err := os.Open(l.steeringPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	doc, err := io.ReadAll(io.LimitReader(f, maxSteeringBytes+1))
	if err != nil {
		return nil, err
	}
	if len(doc) > maxSteeringBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", l.steeringPath(), maxSteeringBytes)
	}
	return doc, nil
}

// PutSteeringState replaces the saved document. Only the active instance
// writes it: a standby's copy is older than the pair's.
func (l *Lease) PutSteeringState(_ context.Context, doc []byte) error {
	if !l.Active() {
		return errors.New("this instance is standby: the steering state is saved by the active instance")
	}
	return writeAtomic(l.steeringPath(), doc, !l.noSync)
}
