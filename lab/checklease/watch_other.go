//go:build !linux

package main

import (
	"fmt"
	"os"
	"time"
)

// armWatch is the non-Linux stub. The lab runs on Linux, where directory
// events cover a release the standby overwrites. Other systems still
// compile and poll the file.
func armWatch(dir string) (int, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return -1, err
	}
	if !fi.IsDir() {
		return -1, fmt.Errorf("%s is not a directory", dir)
	}
	return -1, nil
}

func closeWatch(int) error { return nil }

func waitWatch(_ int, d time.Duration) { time.Sleep(d) }
