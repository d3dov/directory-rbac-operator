package fake

import (
	"context"
	"errors"
	"testing"

	"github.com/d3dov/directory-rbac-operator/internal/ldapclient"
)

func TestGrouperGetGroupMembers(t *testing.T) {
	g := &Grouper{Groups: map[string][]string{
		"cn=data-team,ou=groups,dc=corp,dc=local": {"alice", "bob"},
	}}

	members, err := g.GetGroupMembers(context.Background(), "cn=data-team,ou=groups,dc=corp,dc=local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 2 || members[0] != "alice" || members[1] != "bob" {
		t.Fatalf("unexpected members: %v", members)
	}
}

func TestGrouperGetGroupMembersNotFound(t *testing.T) {
	g := &Grouper{Groups: map[string][]string{}}

	_, err := g.GetGroupMembers(context.Background(), "cn=missing,ou=groups,dc=corp,dc=local")
	if !errors.Is(err, ldapclient.ErrGroupNotFound) {
		t.Fatalf("expected ErrGroupNotFound, got: %v", err)
	}
}

func TestGrouperGetGroupMembersForcedError(t *testing.T) {
	forced := errors.New("simulated query failure")
	g := &Grouper{
		Groups: map[string][]string{"cn=data-team,ou=groups,dc=corp,dc=local": {"alice"}},
		Errors: map[string]error{"cn=data-team,ou=groups,dc=corp,dc=local": forced},
	}

	_, err := g.GetGroupMembers(context.Background(), "cn=data-team,ou=groups,dc=corp,dc=local")
	if !errors.Is(err, forced) {
		t.Fatalf("GetGroupMembers() error = %v, want the forced error even though Groups has an entry", err)
	}
}
