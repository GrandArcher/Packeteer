package span

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

// FuzzPcap reads arbitrary bytes as a capture file and decodes every record.
// The file is operator-supplied but the frames in it are not trusted.
func FuzzPcap(f *testing.F) {
	raw, err := os.ReadFile("testdata/problems.pcap")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add(raw[:24])
	f.Add(raw[:len(raw)-3])
	f.Fuzz(func(t *testing.T, p []byte) {
		pr, err := newPcapReader(bytes.NewReader(p))
		if err != nil {
			return
		}
		for {
			_, rec, err := pr.next()
			if err != nil {
				if !errors.Is(err, io.EOF) && len(rec) != 0 {
					t.Fatalf("record of %d bytes returned with %v", len(rec), err)
				}
				return
			}
			if len(rec) > maxPcapRecord {
				t.Fatalf("record of %d bytes", len(rec))
			}
			if seg, ok := decodeFrame(pr.link, rec); ok && (!seg.src.IsValid() || !seg.dst.IsValid()) {
				t.Fatalf("segment without addresses: %+v", seg)
			}
		}
	})
}
