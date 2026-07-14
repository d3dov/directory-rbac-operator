package ldapclient

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// fakeConn is a minimal ldapConn double. It exists because the
// vjeantet/ldapserver instance backing wire_test.go doesn't parse or emit
// LDAP controls, so it cannot simulate an RFC 2696 paged response or a
// referral - the two behaviors this file's tests cover.
type fakeConn struct {
	searchFunc           func(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	searchWithPagingFunc func(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)

	gotPagingSize uint32
	pagingCalls   int
}

func (f *fakeConn) Bind(string, string) error  { return nil }
func (f *fakeConn) StartTLS(*tls.Config) error { return nil }
func (f *fakeConn) SetTimeout(time.Duration)   {}
func (f *fakeConn) Close() error               { return nil }

func (f *fakeConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return f.searchFunc(req)
}

func (f *fakeConn) SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	f.pagingCalls++
	f.gotPagingSize = pagingSize
	return f.searchWithPagingFunc(req, pagingSize)
}

var _ ldapConn = (*fakeConn)(nil)

func entryWithUID(dn, uid string) *ldap.Entry {
	return ldap.NewEntry(dn, map[string][]string{"uid": {uid}})
}

func TestResolveMembersRequestsRFC2696PagingNotPlainSearch(t *testing.T) {
	const groupDN = "cn=data-team,ou=groups,dc=corp,dc=local"

	conn := &fakeConn{
		searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			t.Fatal("reverse membership query must use SearchWithPaging, not Search")
			return nil, nil
		},
		searchWithPagingFunc: func(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{entryWithUID("uid=alice,ou=people,dc=corp,dc=local", "alice")}}, nil
		},
	}
	c := New(Config{UserSearchBase: "ou=people,dc=corp,dc=local", UsernameAttribute: "uid"})

	members, err := c.resolveMembers(context.Background(), conn, groupDN, ldap.NewEntry(groupDN, nil))
	if err != nil {
		t.Fatalf("resolveMembers() error = %v", err)
	}
	if conn.pagingCalls != 1 {
		t.Fatalf("SearchWithPaging calls = %d, want 1", conn.pagingCalls)
	}
	if got, want := members, []string{"alice"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("resolveMembers() = %v, want %v", got, want)
	}
}

func TestResolveMembersDefaultsPageSizeTo1000(t *testing.T) {
	conn := &fakeConn{
		searchWithPagingFunc: func(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		},
	}
	c := New(Config{UserSearchBase: "ou=people,dc=corp,dc=local", UsernameAttribute: "uid"})

	if _, err := c.resolveMembers(context.Background(), conn, "cn=g,dc=corp,dc=local", ldap.NewEntry("cn=g,dc=corp,dc=local", nil)); err != nil {
		t.Fatalf("resolveMembers() error = %v", err)
	}
	if conn.gotPagingSize != DefaultPageSize {
		t.Fatalf("paging size = %d, want DefaultPageSize (%d)", conn.gotPagingSize, DefaultPageSize)
	}
}

func TestResolveMembersUsesConfiguredPageSize(t *testing.T) {
	conn := &fakeConn{
		searchWithPagingFunc: func(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		},
	}
	c := New(Config{UserSearchBase: "ou=people,dc=corp,dc=local", UsernameAttribute: "uid", PageSize: 50})

	if _, err := c.resolveMembers(context.Background(), conn, "cn=g,dc=corp,dc=local", ldap.NewEntry("cn=g,dc=corp,dc=local", nil)); err != nil {
		t.Fatalf("resolveMembers() error = %v", err)
	}
	if conn.gotPagingSize != 50 {
		t.Fatalf("paging size = %d, want 50", conn.gotPagingSize)
	}
}

func TestResolveMembersFailsExplicitlyOnReferralResponse(t *testing.T) {
	conn := &fakeConn{
		searchWithPagingFunc: func(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultReferral, errors.New("referral to another domain"))
		},
	}
	c := New(Config{UserSearchBase: "ou=people,dc=corp,dc=local", UsernameAttribute: "uid"})

	_, err := c.resolveMembers(context.Background(), conn, "cn=g,dc=corp,dc=local", ldap.NewEntry("cn=g,dc=corp,dc=local", nil))
	if err == nil {
		t.Fatal("resolveMembers() error = nil, want an error when the directory returns a referral instead of a result")
	}
}

func TestResolveMembersIgnoresContinuationReferralsAlongsideEntries(t *testing.T) {
	conn := &fakeConn{
		searchWithPagingFunc: func(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{
				Entries:   []*ldap.Entry{entryWithUID("uid=alice,ou=people,dc=corp,dc=local", "alice")},
				Referrals: []string{"ldap://dc2.corp.local/ou=people,dc=corp,dc=local"},
			}, nil
		},
	}
	c := New(Config{UserSearchBase: "ou=people,dc=corp,dc=local", UsernameAttribute: "uid"})

	members, err := c.resolveMembers(context.Background(), conn, "cn=g,dc=corp,dc=local", ldap.NewEntry("cn=g,dc=corp,dc=local", nil))
	if err != nil {
		t.Fatalf("resolveMembers() error = %v, want nil - continuation referrals alongside entries are logged, not fatal", err)
	}
	if len(members) != 1 || members[0] != "alice" {
		t.Fatalf("members = %v, want [alice]", members)
	}
}

func TestLookupUsernameSkipsReferralMemberDNInsteadOfFailing(t *testing.T) {
	conn := &fakeConn{
		searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultReferral, errors.New("referral to another domain"))
		},
	}
	c := New(Config{UsernameAttribute: "uid"})

	username, err := c.lookupUsername(context.Background(), conn, "uid=alice,ou=people,dc=other,dc=local")
	if err != nil {
		t.Fatalf("lookupUsername() error = %v, want nil - a referral member DN is skipped like a stale one", err)
	}
	if username != "" {
		t.Fatalf("lookupUsername() = %q, want empty (skipped)", username)
	}
}

func TestLookupGroupFailsExplicitlyOnReferralResponse(t *testing.T) {
	conn := &fakeConn{
		searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultReferral, errors.New("referral to another domain"))
		},
	}
	c := New(Config{})

	_, err := c.lookupGroup(context.Background(), conn, "cn=g,dc=corp,dc=local")
	if err == nil {
		t.Fatal("lookupGroup() error = nil, want an error when the directory returns a referral instead of a result")
	}
	if errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("a referral must not be classified as ErrGroupNotFound (that would requeue as if the DN were simply absent): %v", err)
	}
}

func TestClientPageSizeDefaultsAndOverrides(t *testing.T) {
	if got := (&Client{}).pageSize(); got != DefaultPageSize {
		t.Fatalf("pageSize() with zero-value Config = %d, want DefaultPageSize (%d)", got, DefaultPageSize)
	}
	if got := (&Client{cfg: Config{PageSize: 25}}).pageSize(); got != 25 {
		t.Fatalf("pageSize() with PageSize=25 = %d, want 25", got)
	}
}
