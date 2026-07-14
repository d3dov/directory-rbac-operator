package ldapclient

import (
	"sync"

	"golang.org/x/time/rate"
)

// DefaultRate and DefaultBurst are conservative enough for a shared AD
// Global Catalog: those are frequently rate-sensitive shared infrastructure,
// and this operator is rarely the only thing querying one.
const (
	DefaultRate  rate.Limit = 5
	DefaultBurst int        = 10
)

// Limiters is a keyed registry of rate limiters, one per LDAPProvider, so
// every binding reconciling against the same directory shares a single
// request budget regardless of how many CRs reference it - the alternative,
// a limiter per binding, would let request volume scale with binding count
// rather than with the directory's actual capacity.
type Limiters struct {
	Rate  rate.Limit
	Burst int

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

// Get returns the limiter for key, creating it on first use.
func (l *Limiters) Get(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.limiters == nil {
		l.limiters = make(map[string]*rate.Limiter)
	}

	lim, ok := l.limiters[key]
	if !ok {
		lim = rate.NewLimiter(l.rate(), l.burst())
		l.limiters[key] = lim
	}
	return lim
}

// Delete removes key's limiter, e.g. once its LDAPProvider is gone.
// Otherwise long-running operators would accumulate one stale entry per
// deleted provider for as long as the process runs.
func (l *Limiters) Delete(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.limiters, key)
}

func (l *Limiters) rate() rate.Limit {
	if l.Rate == 0 {
		return DefaultRate
	}
	return l.Rate
}

func (l *Limiters) burst() int {
	if l.Burst == 0 {
		return DefaultBurst
	}
	return l.Burst
}
