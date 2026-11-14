package main

import (
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"sort"
)

// fileState is a watched file's content hash; absent is a file that did
// not exist.
type fileState struct {
	absent bool
	sum    [sha256.Size]byte
}

// snapshot is the state of the config files the harness must not change.
type snapshot map[string]fileState

func takeSnapshot(paths []string) (snapshot, error) {
	s := snapshot{}
	for _, p := range paths {
		st, err := readState(p)
		if err != nil {
			return nil, err
		}
		s[p] = st
	}
	return s, nil
}

func readState(path string) (fileState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileState{absent: true}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	return fileState{sum: sha256.Sum256(data)}, nil
}

// changed lists the watched files that were written, created, or removed
// since the snapshot, or can no longer be read.
func (s snapshot) changed() []string {
	var out []string
	for p, was := range s {
		if now, err := readState(p); err != nil || now != was {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
