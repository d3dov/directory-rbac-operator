package ldapclient

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
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
