//go:build linux

package main

import (
	"time"

	"golang.org/x/sys/unix"
)

// armWatch asks the kernel to report replacements of files in dir. The
// lease plugin writes the record with an atomic rename, and the standby
// replaces it again on takeover, so a poll can miss the released record
// when that window is shorter than the interval.
func armWatch(dir string) (int, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return -1, err
	}
	const mask = unix.IN_MOVED_TO | unix.IN_CREATE | unix.IN_CLOSE_WRITE | unix.IN_MODIFY | unix.IN_MOVED_FROM | unix.IN_DELETE
	if _, err := unix.InotifyAddWatch(fd, dir, mask); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func closeWatch(fd int) error { return unix.Close(fd) }

// waitWatch blocks until dir changes or d elapses, then drains the events.
func waitWatch(fd int, d time.Duration) {
	if fd < 0 {
		time.Sleep(d)
		return
	}
	ms := int(d.Milliseconds())
	if ms < 1 {
		ms = 1
	}
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	_, _ = unix.Poll(pfd, ms)
	buf := make([]byte, 8192)
	for {
		if _, err := unix.Read(fd, buf); err != nil {
			return
		}
	}
}
