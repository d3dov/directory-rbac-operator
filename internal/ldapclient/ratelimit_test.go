package ldapclient

import (
	"testing"

	"golang.org/x/time/rate"
)

func TestLimitersGetReturnsSameLimiterForSameKey(t *testing.T) {
	var l Limiters
	a := l.Get("corp-ad")
	b := l.Get("corp-ad")
	if a != b {
		t.Fatal("expected the same limiter instance for the same key")
	}
}

func TestLimitersGetReturnsDistinctLimitersForDistinctKeys(t *testing.T) {
	var l Limiters
	a := l.Get("corp-ad")
	b := l.Get("other-ad")
	if a == b {
		t.Fatal("expected distinct limiter instances for distinct keys")
	}
}

func TestLimitersDeleteResetsKey(t *testing.T) {
	var l Limiters
	a := l.Get("corp-ad")
	l.Delete("corp-ad")
	b := l.Get("corp-ad")
	if a == b {
		t.Fatal("expected a fresh limiter after Delete")
	}
}

func TestLimitersDefaults(t *testing.T) {
	var l Limiters
	lim := l.Get("corp-ad")
	if lim.Limit() != DefaultRate {
		t.Fatalf("Limit() = %v, want %v", lim.Limit(), DefaultRate)
	}
	if lim.Burst() != DefaultBurst {
		t.Fatalf("Burst() = %v, want %v", lim.Burst(), DefaultBurst)
	}
}

func TestLimitersCustomRateAndBurst(t *testing.T) {
	l := Limiters{Rate: rate.Limit(2), Burst: 4}
	lim := l.Get("corp-ad")
	if lim.Limit() != 2 {
		t.Fatalf("Limit() = %v, want 2", lim.Limit())
	}
	if lim.Burst() != 4 {
		t.Fatalf("Burst() = %v, want 4", lim.Burst())
	}
}
