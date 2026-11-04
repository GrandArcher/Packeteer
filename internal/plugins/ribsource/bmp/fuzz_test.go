package bmp

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// FuzzBMPStream feeds arbitrary bytes through the framing and the decoder a
// router session uses. A router is untrusted input: whatever it sends must
// end the stream with an error or yield events, never a panic.
func FuzzBMPStream(f *testing.F) {
	raw, err := os.ReadFile(fixture)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	var msgs [][]byte
	if err := readMessages(bytes.NewReader(raw), func(m []byte) error { msgs = append(msgs, m); return nil }); err != nil {
		f.Logf("fixture ends with %v", err)
	}
	for _, m := range msgs {
		f.Add(m)
	}
	f.Add([]byte{3, 0, 0, 0, 6, 5})
	f.Fuzz(func(t *testing.T, p []byte) {
		d := newDecoder(router, true, quietLog)
		d.adjOut = true
		_ = readMessages(bytes.NewReader(p), func(m []byte) error {
			if len(m) > maxMessage {
				t.Fatalf("framing passed a %d byte message", len(m))
			}
			_, stop := d.message(m)
			if stop {
				return io.EOF
			}
			return nil
		})
	})
}
