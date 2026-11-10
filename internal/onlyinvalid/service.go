package onlyinvalid

import (
	"context"
	"time"
)

// Service is the detector and, when the slurm block is set, the
// exceptions.
type Service struct {
	*Detector
	// Exceptions is nil without the slurm block.
	Exceptions *Exceptions
}

// Run scans after a short delay and then every scan interval until ctx
// ends, and checks the review reminders after each scan.
func (s *Service) Run(ctx context.Context) {
	wait := firstScanDelay
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		s.Scan(ctx)
		if s.Exceptions != nil {
			s.Exceptions.Remind()
		}
		wait = scanInterval
	}
}
