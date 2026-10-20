package flow

import (
	"net/netip"
	"time"
)

// ingest decodes one datagram and counts it on the calling goroutine, the
// path a reader and a worker take together.
func (s *Source) ingest(at time.Time, exporter netip.Addr, payload []byte) {
	obs, _ := s.dec.decode(exporter, payload)
	s.apply(at, obs)
	putObs(obs)
}
