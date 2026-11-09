// Command sendflow sends synthetic NetFlow v5 to a collector at steady
// rates. lab/e2e-anomaly.sh runs it to feed Packeteer's flow source with a
// baseline and then floods, without any real traffic. Documentation
// prefixes only.
//
//	sendflow -to 192.0.2.10:2055 -rates /tmp/rates.txt -every 200ms
//
// The rates file is re-read before every export, so a script changes the
// traffic by rewriting it (write a new file and rename it over the old
// one). Each line is "destination protocol mbps", for example
// "198.51.100.10 udp 1.5"; blank lines and lines starting with # are
// ignored. A file that cannot be read or parsed keeps the last good rates.
// Each export carries one record per line with the bytes that rate sends
// in one interval.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// flow is one rates line.
type flow struct {
	dst   netip.Addr
	proto uint8
	mbps  float64
}

var protocols = map[string]uint8{"icmp": 1, "tcp": 6, "udp": 17}

// parse reads a rates file.
func parse(text string) ([]flow, error) {
	var out []flow
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("line %d: want \"destination protocol mbps\"", i+1)
		}
		dst, err := netip.ParseAddr(f[0])
		if err != nil || !dst.Is4() {
			return nil, fmt.Errorf("line %d: %q is not an IPv4 address", i+1, f[0])
		}
		proto, ok := protocols[f[1]]
		if !ok {
			n, err := strconv.ParseUint(f[1], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("line %d: protocol %q", i+1, f[1])
			}
			proto = uint8(n)
		}
		mbps, err := strconv.ParseFloat(f[2], 64)
		if err != nil || mbps < 0 || mbps > 100000 {
			return nil, fmt.Errorf("line %d: mbps %q (0-100000)", i+1, f[2])
		}
		out = append(out, flow{dst: dst, proto: proto, mbps: mbps})
	}
	if len(out) > 30 {
		return nil, errors.New("at most 30 flows (one NetFlow v5 export)")
	}
	return out, nil
}

// export builds one NetFlow v5 export: each flow's bytes for one interval.
func export(flows []flow, every time.Duration, seq uint32, now time.Time) []byte {
	b := make([]byte, 24+48*len(flows))
	binary.BigEndian.PutUint16(b[0:], 5)
	binary.BigEndian.PutUint16(b[2:], uint16(len(flows)))
	binary.BigEndian.PutUint32(b[8:], uint32(now.Unix()))
	binary.BigEndian.PutUint32(b[16:], seq)
	src := netip.MustParseAddr("192.0.2.200").As4()
	for i, f := range flows {
		o := 24 + 48*i
		octets := uint32(f.mbps * 1e6 / 8 * every.Seconds())
		dst := f.dst.As4()
		copy(b[o:o+4], src[:])
		copy(b[o+4:o+8], dst[:])
		binary.BigEndian.PutUint32(b[o+16:], max(octets/1000, 1))
		binary.BigEndian.PutUint32(b[o+20:], octets)
		b[o+38] = f.proto
	}
	return b
}

func main() {
	to := flag.String("to", "", "collector host:port")
	rates := flag.String("rates", "", "rates file, re-read before every export")
	every := flag.Duration("every", 200*time.Millisecond, "export interval")
	flag.Parse()
	if *to == "" || *rates == "" || *every <= 0 {
		flag.Usage()
		os.Exit(2)
	}
	conn, err := net.Dial("udp", *to)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	var flows []flow
	var seq uint32
	tick := time.NewTicker(*every)
	defer tick.Stop()
	for now := range tick.C {
		if raw, err := os.ReadFile(*rates); err == nil {
			if f, err := parse(string(raw)); err == nil {
				flows = f
			} else {
				log.Printf("rates: %v (keeping the last good rates)", err)
			}
		}
		if len(flows) == 0 {
			continue
		}
		if _, err := conn.Write(export(flows, *every, seq, now)); err != nil {
			log.Printf("send: %v", err)
		}
		seq += uint32(len(flows))
	}
}
