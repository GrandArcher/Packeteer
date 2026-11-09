package probe

import "golang.org/x/time/rate"

func newTokenLimiterForTest(pps, burst int) Limiter {
	return rate.NewLimiter(rate.Limit(pps), burst)
}
