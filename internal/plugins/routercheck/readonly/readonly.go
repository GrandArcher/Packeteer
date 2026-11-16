// Package readonly holds what every router check backend (#626) shares: the
// allowlist each command must pass before it is written to the router, and
// the socket and file access that keeps their paths out of errors. The
// paths come from the environment and count as credentials.
package readonly

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"regexp"

	"github.com/GrandArcher/Packeteer/internal/plugins/exporter/sinkcfg"
)

// ErrRefused is returned for a command that is not on the backend's
// allowlist. Nothing is written to the router.
var ErrRefused = errors.New("not a read command on this backend's allowlist; refused")

// Allowlist is the fixed set of commands a backend may send. Each pattern
// matches a whole command.
type Allowlist []*regexp.Regexp

// NewAllowlist compiles patterns, each anchored to the whole command.
func NewAllowlist(patterns ...string) Allowlist {
	out := make(Allowlist, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(`\A(?:` + p + `)\z`)
	}
	return out
}

// Check returns nil when cmd is on the list.
func (a Allowlist) Check(cmd string) error {
	for _, re := range a {
		if re.MatchString(cmd) {
			return nil
		}
	}
	return fmt.Errorf("%q: %w", cmd, ErrRefused)
}

// Name is the pattern for a policy name taken from the router's own output
// and put into a command. A name with anything else (a space, a newline, a
// NUL) is not sent.
const Name = `[A-Za-z0-9_.:-]{1,63}`

// Path reads the absolute path held by the environment variable name, which
// the config sets in field. With checkOnly only the variable name is checked:
// the config editor validates a file for a process that may not have it yet.
func Path(getenv func(string) string, field, name string, checkOnly bool) (string, error) {
	if checkOnly {
		getenv = func(string) string { return "/" }
	}
	p, err := sinkcfg.Secret(getenv, field, name)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%s: %s must hold an absolute path", field, name)
	}
	return p, nil
}

// Dial connects to the router's unix socket. The error names the cause
// (refused, missing, permission denied) and never the path.
func Dial(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("connect to the router socket: %w", Scrub(err))
	}
	if dl, ok := ctx.Deadline(); ok {
		if err := c.SetDeadline(dl); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("connect to the router socket: %w", Scrub(err))
		}
	}
	return c, nil
}

// Scrub drops the path from a socket or file error and keeps its cause.
func Scrub(err error) error {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
