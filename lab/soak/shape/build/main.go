// Command build rebuilds lab/soak/shape/shape.json from an MRT TABLE_DUMP_V2
// file (a RIPE RIS or RouteViews bview, gzip or plain). It reads the dump,
// pools the full-feed peers (at least 90 percent of the largest peer's
// routes), and writes counts only: no prefix and no AS number leaves this
// program.
//
//	go run ./lab/soak/shape/build -source "RIPE RIS rrc00 bview" -date 2026-10-21 bview.gz > lab/soak/shape/shape.json
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/mrt"

	"github.com/GrandArcher/Packeteer/lab/soak/shape"
)

func main() {
	source := flag.String("source", "", "label for the dump, for example \"RIPE RIS rrc00 bview\"")
	date := flag.String("date", "", "date the dump was taken, for example 2026-10-21")
	flag.Parse()
	if flag.NArg() != 1 || *source == "" || *date == "" {
		fmt.Fprintln(os.Stderr, "usage: build -source LABEL -date DATE DUMP")
		os.Exit(2)
	}
	if err := run(flag.Arg(0), *source, *date, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}
}

func run(path, source, date string, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if gz, err := gzip.NewReader(f); err == nil {
		r = gz
	} else if _, serr := f.Seek(0, io.SeekStart); serr != nil {
		return serr
	}
	peers, err := read(r)
	if err != nil {
		return err
	}
	most := 0
	for _, a := range peers {
		most = max(most, a.Routes())
	}
	if most == 0 {
		return errors.New("no routes in the dump")
	}
	var feeds []shape.Shape
	for _, a := range peers {
		if a.Routes()*10 >= most*9 {
			feeds = append(feeds, a.Shape())
		}
	}
	s := shape.Pool(source, date, feeds)
	if err := s.Validate(); err != nil {
		return err
	}
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	return e.Encode(s)
}

// read feeds every RIB entry to the accumulator of its peer.
func read(r io.Reader) (map[uint16]*shape.Accumulator, error) {
	peers := map[uint16]*shape.Accumulator{}
	skipped := 0
	defer func() { fmt.Fprintf(os.Stderr, "build: %d records skipped\n", skipped) }()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	sc.Split(mrt.SplitMrt)
	for sc.Scan() {
		data := sc.Bytes()
		h := &mrt.MRTHeader{}
		if err := h.DecodeFromBytes(data[:mrt.MRT_COMMON_HEADER_LEN]); err != nil {
			return nil, err
		}
		if h.Type != mrt.TABLE_DUMPv2 {
			continue
		}
		switch mrt.MRTSubTypeTableDumpv2(h.SubType) {
		case mrt.RIB_IPV4_UNICAST, mrt.RIB_IPV6_UNICAST:
		default:
			continue
		}
		m, err := mrt.ParseMRTBody(h, data[mrt.MRT_COMMON_HEADER_LEN:])
		if err != nil {
			// A few records in a live dump carry attributes the parser
			// rejects. Skipping one drops its prefix from the counts.
			skipped++
			continue
		}
		rib := m.Body.(*mrt.Rib)
		v6 := rib.RouteFamily == bgp.RF_IPv6_UC
		plen := int(prefixLen(rib.Prefix))
		for _, e := range rib.Entries {
			a := peers[e.PeerIndex]
			if a == nil {
				a = shape.NewAccumulator()
				peers[e.PeerIndex] = a
			}
			a.Add(v6, plen, e.PathAttributes)
		}
	}
	return peers, sc.Err()
}

func prefixLen(p bgp.AddrPrefixInterface) uint8 {
	switch v := p.(type) {
	case *bgp.IPAddrPrefix:
		return v.Length
	case *bgp.IPv6AddrPrefix:
		return v.Length
	}
	return 0
}
