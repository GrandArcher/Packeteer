package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// userHZ is the clock tick of /proc/<pid>/stat CPU times. Linux fixes it at
// 100 for userspace on every architecture.
const userHZ = 100

// proc is one read of the Packeteer process from /proc. The container
// runs with --network host but its own PID namespace; the host PID comes
// from `docker inspect`.
type proc struct {
	RSS     uint64  // bytes
	HWM     uint64  // peak RSS, bytes
	Threads int     //
	CPU     float64 // user+system seconds since start
}

func readProc(root string, pid int) (proc, error) {
	var p proc
	status, err := os.ReadFile(fmt.Sprintf("%s/%d/status", root, pid))
	if err != nil {
		return p, err
	}
	if p, err = parseStatus(string(status)); err != nil {
		return p, err
	}
	stat, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", root, pid))
	if err != nil {
		return p, err
	}
	p.CPU, err = parseStatCPU(string(stat))
	return p, err
}

func parseStatus(s string) (proc, error) {
	var p proc
	var seen int
	for line := range strings.Lines(s) {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "VmRSS":
			p.RSS, seen = n*1024, seen|1
		case "VmHWM":
			p.HWM, seen = n*1024, seen|2
		case "Threads":
			p.Threads, seen = int(n), seen|4
		}
	}
	if seen != 7 {
		return p, errors.New("status: VmRSS, VmHWM, or Threads missing")
	}
	return p, nil
}

// parseStatCPU returns utime+stime in seconds. The command name in field
// 2 may contain spaces, so fields are counted after its closing ")".
func parseStatCPU(s string) (float64, error) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, errors.New("stat: no command")
	}
	f := strings.Fields(s[i+1:])
	// f[0] is field 3 (state); utime and stime are fields 14 and 15.
	if len(f) < 13 {
		return 0, errors.New("stat: short")
	}
	u, err1 := strconv.ParseUint(f[11], 10, 64)
	st, err2 := strconv.ParseUint(f[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, errors.New("stat: bad cpu times")
	}
	return float64(u+st) / userHZ, nil
}

// udpStats is the host's UDP counters. Packeteer's flow socket is in the
// host network namespace, so a datagram the collector was too slow to
// read shows up as RcvbufErrors.
type udpStats struct {
	In, RcvbufErrors uint64
}

func readUDP(path string) (udpStats, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return udpStats{}, err
	}
	return parseSNMP(string(b))
}

func parseSNMP(s string) (udpStats, error) {
	var names []string
	for line := range strings.Lines(s) {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "Udp:" {
			continue
		}
		if names == nil {
			names = f[1:]
			continue
		}
		var u udpStats
		got := 0
		for j, n := range names {
			if j+1 >= len(f) {
				break
			}
			v, err := strconv.ParseUint(f[j+1], 10, 64)
			if err != nil {
				continue
			}
			switch n {
			case "InDatagrams":
				u.In, got = v, got|1
			case "RcvbufErrors":
				u.RcvbufErrors, got = v, got|2
			}
		}
		if got != 3 {
			return u, errors.New("snmp: Udp InDatagrams or RcvbufErrors missing")
		}
		return u, nil
	}
	return udpStats{}, errors.New("snmp: no Udp lines")
}

// metrics is what the harness reads from Packeteer's /metrics.
type metrics struct {
	Ready       bool
	SessionUp   bool
	RIBPrefixes int
}

func parseMetrics(r io.Reader) (metrics, error) {
	var m metrics
	seen := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		name, val, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
		if err != nil {
			continue
		}
		switch {
		case name == "packeteer_ready":
			m.Ready, seen = v == 1, seen|1
		case name == "packeteer_rib_prefixes":
			m.RIBPrefixes, seen = int(v), seen|2
		case strings.HasPrefix(name, "packeteer_bgp_session_up{"):
			m.SessionUp = m.SessionUp || v == 1
		}
	}
	if err := sc.Err(); err != nil {
		return m, err
	}
	if seen != 3 {
		return m, errors.New("metrics: packeteer_ready or packeteer_rib_prefixes missing")
	}
	return m, nil
}

// overview is the part of /api/overview the harness checks.
type overview struct {
	Mode   string `json:"mode"`
	Counts struct {
		Prefixes int `json:"prefixes"`
		Measured int `json:"measured"`
		InRIB    int `json:"in_rib"`
	} `json:"counts"`
}

type opsAPI struct {
	base   string
	client *http.Client
}

func newAPI(base string) *opsAPI {
	return &opsAPI{base: strings.TrimRight(base, "/"), client: &http.Client{Timeout: 10 * time.Second}}
}

// get fetches path and returns the body read time.
func (a *opsAPI) get(ctx context.Context, path string, fn func(io.Reader) error) (time.Duration, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		return 0, err
	}
	rsp, err := a.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET %s: %s", path, rsp.Status)
	}
	err = fn(rsp.Body)
	return time.Since(start), err
}

func (a *opsAPI) metrics(ctx context.Context) (metrics, time.Duration, error) {
	var m metrics
	d, err := a.get(ctx, "/metrics", func(r io.Reader) (err error) {
		m, err = parseMetrics(r)
		return err
	})
	return m, d, err
}

func (a *opsAPI) overview(ctx context.Context) (overview, time.Duration, error) {
	var o overview
	d, err := a.get(ctx, "/api/overview", func(r io.Reader) error {
		return json.NewDecoder(r).Decode(&o)
	})
	return o, d, err
}
