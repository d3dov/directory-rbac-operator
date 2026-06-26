package ldapclient

import (
	"context"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/time/rate"
)

func TestUsernames(t *testing.T) {
	entries := []*ldap.Entry{
		ldap.NewEntry("uid=alice,ou=people,dc=corp,dc=local", map[string][]string{"uid": {"alice"}}),
		ldap.NewEntry("uid=bob,ou=people,dc=corp,dc=local", map[string][]string{"uid": {"bob"}}),
		ldap.NewEntry("uid=nouid,ou=people,dc=corp,dc=local", map[string][]string{}),
	}

	got := usernames(entries, "uid")
	want := []string{"alice", "bob"}

	if len(got) != len(want) {
		t.Fatalf("usernames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("usernames()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestClientRespectsRateLimiter(t *testing.T) {
	// Burst 0 makes Wait fail synchronously (n=1 exceeds the limiter's
	// burst) without ever consulting the context or attempting a dial, so
	// this proves the limiter gates connectAndBind without needing a real
	// (or even reachable) directory.
	limiter := rate.NewLimiter(rate.Limit(1), 0)
	c := New(Config{URL: "ldap://127.0.0.1:0", Limiter: limiter})

	_, err := c.GetGroupMembers(context.Background(), "cn=test,dc=example,dc=com")
	if err == nil {
		t.Fatal("expected an error from a burst-0 rate limiter")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("expected a rate-limit error, got: %v", err)
	}
}
