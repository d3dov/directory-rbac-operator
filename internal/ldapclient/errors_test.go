package ldapclient

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestLookupGroupReturnsGenericErrorForNonReferralNonNotFound(t *testing.T) {
	conn := &fakeConn{
		searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultOperationsError, errors.New("boom"))
		},
	}
	c := New(Config{})

	_, err := c.lookupGroup(context.Background(), conn, "cn=g,dc=corp,dc=local")
	if err == nil {
		t.Fatal("lookupGroup() error = nil, want a generic error")
	}
	if errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("an operations error must not be classified as ErrGroupNotFound: %v", err)
	}
}

func TestLookupGroupReturnsErrGroupNotFoundWhenSearchSucceedsWithNoEntries(t *testing.T) {
	conn := &fakeConn{
		searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		},
	}
	c := New(Config{})

	_, err := c.lookupGroup(context.Background(), conn, "cn=g,dc=corp,dc=local")
	if !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("lookupGroup() error = %v, want ErrGroupNotFound", err)
	}
}

func TestResolveMembersPropagatesGenericMemberLookupError(t *testing.T) {
	const groupDN = "cn=g,dc=corp,dc=local"
	memberDN := "uid=alice,ou=people,dc=corp,dc=local"

	conn := &fakeConn{
		searchWithPagingFunc: func(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error) {
			// No memberOf hits: forces the fallback to groupEntry's own
			// member attribute, which is what actually drives lookupUsername.
			return &ldap.SearchResult{}, nil
		},
		searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultOperationsError, errors.New("boom"))
		},
	}
	c := New(Config{UsernameAttribute: "uid"})
	groupEntry := ldap.NewEntry(groupDN, map[string][]string{"member": {memberDN}})

	_, err := c.resolveMembers(context.Background(), conn, groupDN, groupEntry)
	if err == nil {
		t.Fatal("resolveMembers() error = nil, want the member lookup's error to propagate")
	}
}

func TestLookupUsernameSkipsStaleNoSuchObjectMemberDN(t *testing.T) {
	conn := &fakeConn{
		searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
		},
	}
	c := New(Config{UsernameAttribute: "uid"})

	username, err := c.lookupUsername(context.Background(), conn, "uid=deleted,ou=people,dc=corp,dc=local")
	if err != nil {
		t.Fatalf("lookupUsername() error = %v, want nil - a stale member DN is skipped, not fatal", err)
	}
	if username != "" {
		t.Fatalf("lookupUsername() = %q, want empty (skipped)", username)
	}
}

func TestLookupUsernameReturnsEmptyWhenSearchSucceedsWithNoEntries(t *testing.T) {
	conn := &fakeConn{
		searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		},
	}
	c := New(Config{UsernameAttribute: "uid"})

	username, err := c.lookupUsername(context.Background(), conn, "uid=alice,ou=people,dc=corp,dc=local")
	if err != nil {
		t.Fatalf("lookupUsername() error = %v, want nil", err)
	}
	if username != "" {
		t.Fatalf("lookupUsername() = %q, want empty", username)
	}
}

func TestLookupUsernameReturnsGenericError(t *testing.T) {
	conn := &fakeConn{
		searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultOperationsError, errors.New("boom"))
		},
	}
	c := New(Config{UsernameAttribute: "uid"})

	_, err := c.lookupUsername(context.Background(), conn, "uid=alice,ou=people,dc=corp,dc=local")
	if err == nil {
		t.Fatal("lookupUsername() error = nil, want the generic error to propagate")
	}
}
