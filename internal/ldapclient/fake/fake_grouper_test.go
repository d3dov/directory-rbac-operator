package fake

import (
	"context"
	"errors"
	"testing"

	"github.com/denis-da-engineer/directory-rbac-operator/internal/ldapclient"
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
