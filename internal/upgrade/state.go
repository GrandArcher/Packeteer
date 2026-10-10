package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Layout under upgrade.dir:
//
//	state.json                 which version should run, and the one before
//	versions/<version>/packeteer
//
// The installed binary (the image's, or the one the operator put on the
// host) is never overwritten: it is the "base". A staged version runs
// because the base hands over to it at start (see Relaunch). Deleting
// state.json, or starting a different base version, returns to the base.

// MaxAttempts is how many times a staged version may start without
// confirming it came up before the launcher goes back to the previous one.
const MaxAttempts = 2

// Entry is one runnable version.
type Entry struct {
	Version string `json:"version"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256,omitempty"`
}

func (e Entry) zero() bool { return e.Path == "" }

// State is state.json.
type State struct {
	// BaseVersion and BasePath identify the installed binary the staged
	// versions were set up from. A different base (a newer image)
	// discards the state.
	BaseVersion string `json:"base_version"`
	BasePath    string `json:"base_path"`
	// Active is what should run. Its Path equals BasePath when the base
	// itself runs.
	Active Entry `json:"active"`
	// Previous is the rollback target. Zero when there is none.
	Previous Entry `json:"previous"`
	// Attempts counts starts of Active since it was chosen; Confirmed is
	// set once it has stayed up.
	Attempts  int       `json:"attempts"`
	Confirmed bool      `json:"confirmed"`
	LastError string    `json:"last_error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type store struct{ dir string }

func (s store) statePath() string { return filepath.Join(s.dir, "state.json") }

func (s store) versionPath(version string) string {
	return filepath.Join(s.dir, "versions", Normalize(version), "packeteer")
}

// load reads state.json. A missing file is (nil, nil).
func (s store) load() (*State, error) {
	data, err := os.ReadFile(s.statePath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", s.statePath(), err)
	}
	return &st, nil
}

func (s store) save(st *State, now time.Time) error {
	st.UpdatedAt = now.UTC()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, "state-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.statePath())
}

// fileSHA256 is the hex digest of the file at path.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// prune removes staged versions other than the ones state keeps.
func (s store) prune(st *State) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "versions"))
	if err != nil {
		return
	}
	keep := map[string]bool{Normalize(st.Active.Version): true, Normalize(st.Previous.Version): true}
	for _, e := range entries {
		if !keep[e.Name()] {
			_ = os.RemoveAll(filepath.Join(s.dir, "versions", e.Name()))
		}
	}
}
