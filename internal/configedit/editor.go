// Package configedit is the validated config editor and the first-run
// wizard behind the ops API (#34). The editor reads and writes the one
// mounted config file. A write is accepted only after the same checks the
// controller runs at start (config.Load's parser and validator, the
// runtime environment, and every plugin's own config), and the file on
// disk is read back through config.Load before the write is reported
// done. Nothing here announces. A write that differs only in keys the
// controller can apply online takes effect when the controller applies
// it (SIGHUP, or PUT /api/config when every change is online). Any other
// change waits for a restart. Reverting to hand-edited files needs
// nothing: the file is a plain YAML file.
package configedit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// MaxSize bounds a config file written through the editor.
const MaxSize = 1 << 20

// Errors.
var (
	// ErrConflict is a write whose base hash is not the file on disk:
	// someone else changed it since it was read.
	ErrConflict = errors.New("config file changed since it was read; reload and edit again")
	// ErrInvalid wraps a config that fails validation. The file is not
	// touched.
	ErrInvalid = errors.New("config is invalid")
	// ErrConfirmInject is a write that turns mode inject on without the
	// explicit confirmation.
	ErrConfirmInject = errors.New("this config turns mode inject on; confirm it explicitly (confirm_inject)")
	// ErrTooLarge is a config over MaxSize.
	ErrTooLarge = errors.New("config is larger than 1 MiB")
)

// Checker runs every check the controller runs at start on a candidate
// file and returns the loaded config. It must not start anything.
type Checker func(data []byte) (*config.Config, error)

// Differ lists what differs between the running config and a candidate.
// restart are the keys that need a restart. online are the keys a reload
// applies while running. A candidate with both is not applied online.
type Differ func(running, next *config.Config) (restart, online []string)

// Editor edits one config file. It is safe for concurrent use.
type Editor struct {
	path    string
	check   Checker
	diff    Differ
	running *config.Config
	mu      sync.Mutex
}

// New returns an editor for path. running is the config the controller
// runs with; diffs are against it.
func New(path string, running *config.Config, check Checker, diff Differ) (*Editor, error) {
	if path == "" || check == nil {
		return nil, errors.New("configedit: path and checker are required")
	}
	return &Editor{path: path, check: check, diff: diff, running: running}, nil
}

// SetRunning replaces the config diffs are against. The controller calls
// it after a SIGHUP reload applies a new file.
func (e *Editor) SetRunning(running *config.Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.running = running
}

// File is the config file as it is on disk.
type File struct {
	Path   string `json:"path"`
	YAML   string `json:"yaml"`
	SHA256 string `json:"sha256"`
}

// Result is the outcome of checking a candidate.
type Result struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
	Mode   string   `json:"mode,omitempty"`
	// Changed lists the keys that differ from the running config.
	Changed []string `json:"changed,omitempty"`
	// RestartRequired is true when a key that cannot apply online changed.
	// The new file applies on the next start.
	RestartRequired bool `json:"restart_required"`
	// ReloadOnline is true when every change can apply while running
	// (SIGHUP, or PUT /api/config). A mix of online and restart keys is
	// not online.
	ReloadOnline bool `json:"reload_online"`
	// EnablesInject is true when the candidate is mode inject and the
	// file on disk is not.
	EnablesInject bool `json:"enables_inject"`
}

// Hash is the hex SHA-256 of data.
func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Read returns the file on disk.
func (e *Editor) Read() (File, error) {
	data, err := os.ReadFile(e.path)
	if err != nil {
		return File{}, err
	}
	return File{Path: e.path, YAML: string(data), SHA256: Hash(data)}, nil
}

// Check validates a candidate without writing it.
func (e *Editor) Check(data []byte) Result {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.checkLocked(data)
}

func (e *Editor) checkLocked(data []byte) Result {
	if len(data) > MaxSize {
		return Result{Errors: []string{ErrTooLarge.Error()}}
	}
	next, err := e.check(data)
	if err != nil {
		return Result{Errors: splitErrors(err)}
	}
	res := Result{Valid: true, Mode: next.Mode}
	if e.diff != nil && e.running != nil {
		restart, online := e.diff(e.running, next)
		res.Changed = append(append([]string{}, restart...), online...)
		slices.Sort(res.Changed)
		res.RestartRequired = len(restart) > 0
		res.ReloadOnline = len(online) > 0 && len(restart) == 0
	}
	res.EnablesInject = next.Mode == config.ModeInject && e.diskMode() != config.ModeInject
	return res
}

// diskMode is the mode of the file on disk, or "" when it does not load.
func (e *Editor) diskMode() string {
	cur, err := config.Load(e.path)
	if err != nil {
		if e.running != nil {
			return e.running.Mode
		}
		return ""
	}
	return cur.Mode
}

// Save writes data when base is the hash of the file on disk and data
// passes every check. A candidate that turns inject on also needs
// confirmInject. The file is read back through config.Load before Save
// returns.
func (e *Editor) Save(data []byte, base string, confirmInject bool) (File, Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cur, err := os.ReadFile(e.path)
	if err != nil {
		return File{}, Result{}, err
	}
	if base == "" || base != Hash(cur) {
		return File{}, Result{}, ErrConflict
	}
	res := e.checkLocked(data)
	if !res.Valid {
		return File{}, res, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(res.Errors, "; "))
	}
	if res.EnablesInject && !confirmInject {
		return File{}, res, ErrConfirmInject
	}
	if err := writeFile(e.path, data, cur); err != nil {
		return File{}, res, fmt.Errorf("write %s: %w", e.path, err)
	}
	// Round trip: what is on disk must be what was checked.
	back, err := os.ReadFile(e.path)
	if err != nil {
		return File{}, res, fmt.Errorf("read back %s: %w", e.path, err)
	}
	if string(back) != string(data) {
		return File{}, res, fmt.Errorf("read back %s: content differs from what was written", e.path)
	}
	if _, err := config.Load(e.path); err != nil {
		return File{}, res, fmt.Errorf("read back %s: %w", e.path, err)
	}
	return File{Path: e.path, YAML: string(data), SHA256: Hash(data)}, res, nil
}

// writeFile replaces path with data. It first writes a temporary file
// next to it and renames it into place (atomic). A single-file bind
// mount cannot be renamed over, and its directory may be read-only; then
// the file is rewritten in place, and restored to old if that fails. If
// the restore fails too, old is saved to a temporary file named in the
// error, so the last good config is never lost.
func writeFile(path string, data, old []byte) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if err := renameInto(path, data, mode); err == nil {
		return nil
	}
	werr := overwrite(path, data)
	if werr == nil {
		return nil
	}
	if rerr := overwrite(path, old); rerr != nil {
		kept := "could not keep a copy"
		if f, err := os.CreateTemp("", "packeteer-config-*.yaml"); err == nil {
			_, err = f.Write(old)
			if cerr := f.Close(); err == nil && cerr == nil {
				kept = "the previous file is saved at " + f.Name()
			}
		}
		return fmt.Errorf("%w; restoring the previous file failed too (%v); %s", werr, rerr, kept)
	}
	return werr
}

// overwrite rewrites path in place with data: it writes over the old
// content first and only then cuts the tail, so the file is never empty
// while it is written.
var overwrite = func(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.WriteAt(data, 0)
	if werr == nil {
		werr = f.Truncate(int64(len(data)))
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

func renameInto(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".edit-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// splitErrors turns a joined validation error into one line per problem.
func splitErrors(err error) []string {
	var out []string
	for _, line := range strings.Split(err.Error(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
