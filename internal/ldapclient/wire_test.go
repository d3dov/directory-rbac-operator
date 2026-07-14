package ldapclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/vjeantet/ldapserver"
)

// These tests run a real (if minimal) LDAP server in-process via
// vjeantet/ldapserver, so Client's dial/StartTLS/bind/search wire behavior
// gets exercised for real rather than only through the fake.Grouper used
// everywhere else. Query construction, username normalization and
// rate-limiter interaction are covered by the table-driven tests elsewhere
// in this package instead - a real server buys little for those.

const (
	testBindDN       = "cn=svc,dc=corp,dc=local"
	testBindPassword = "s3cret"
)

func init() {
	ldapserver.Logger = ldapserver.DiscardingLogger
}

func startTestServer(t *testing.T, routes *ldapserver.RouteMux) string {
	t.Helper()

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	server := ldapserver.NewServer()
	server.Handle(routes)

	go func() {
		_ = server.ListenAndServe(addr)
	}()
	t.Cleanup(server.Stop)

	waitForListener(t, addr)
	return addr
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s never became reachable", addr)
}

// simpleBindHandler is a reusable test fixture: dn/password are parameters
// (even though every current test happens to pass testBindDN) so future
// tests can exercise a mismatched-DN bind failure without a new handler.
//
//nolint:unparam // see comment above
func simpleBindHandler(dn, password string) ldapserver.HandlerFunc {
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		r := m.GetBindRequest()
		if string(r.Name()) == dn && string(r.AuthenticationSimple()) == password {
			w.Write(ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess))
			return
		}
		w.Write(ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials))
	}
}

func TestClientPingSucceedsOnValidBind(t *testing.T) {
	routes := ldapserver.NewRouteMux()
	routes.Bind(simpleBindHandler(testBindDN, testBindPassword))
	addr := startTestServer(t, routes)

	c := New(Config{URL: "ldap://" + addr, BindDN: testBindDN, BindPassword: testBindPassword, InsecureSkipTLS: true})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() = %v, want nil", err)
	}
}

func TestClientPingFailsOnInvalidBindWithoutErrGroupNotFound(t *testing.T) {
	routes := ldapserver.NewRouteMux()
	routes.Bind(simpleBindHandler(testBindDN, testBindPassword))
	addr := startTestServer(t, routes)

	c := New(Config{URL: "ldap://" + addr, BindDN: testBindDN, BindPassword: "wrong", InsecureSkipTLS: true})
	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected a bind error")
	}
	if errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("a bind failure must never be classified as ErrGroupNotFound: %v", err)
	}
}

func TestClientGetGroupMembersReturnsErrGroupNotFound(t *testing.T) {
	routes := ldapserver.NewRouteMux()
	routes.Bind(simpleBindHandler(testBindDN, testBindPassword))
	routes.Search(func(w ldapserver.ResponseWriter, _ *ldapserver.Message) {
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultNoSuchObject))
	})
	addr := startTestServer(t, routes)

	c := New(Config{
		URL: "ldap://" + addr, BindDN: testBindDN, BindPassword: testBindPassword, InsecureSkipTLS: true,
		UserSearchBase: "ou=people,dc=corp,dc=local", UsernameAttribute: "uid",
	})

	_, err := c.GetGroupMembers(context.Background(), "cn=missing,ou=groups,dc=corp,dc=local")
	if !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("GetGroupMembers() error = %v, want ErrGroupNotFound", err)
	}
}

func TestClientGetGroupMembersReverseQuery(t *testing.T) {
	const (
		groupDN        = "cn=data-team,ou=groups,dc=corp,dc=local"
		userSearchBase = "ou=people,dc=corp,dc=local"
	)
	var gotFilter string

	routes := ldapserver.NewRouteMux()
	routes.Bind(simpleBindHandler(testBindDN, testBindPassword))
	routes.Search(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		r := m.GetSearchRequest()
		base := string(r.BaseObject())
		switch {
		case int(r.Scope()) == ldap.ScopeBaseObject && base == groupDN:
			w.Write(ldapserver.NewSearchResultEntry(groupDN))
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
		case int(r.Scope()) == ldap.ScopeWholeSubtree && base == userSearchBase:
			gotFilter = r.FilterString()
			e1 := ldapserver.NewSearchResultEntry("uid=alice," + userSearchBase)
			e1.AddAttribute("uid", "alice")
			w.Write(e1)
			e2 := ldapserver.NewSearchResultEntry("uid=bob," + userSearchBase)
			e2.AddAttribute("uid", "bob")
			w.Write(e2)
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
		default:
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultNoSuchObject))
		}
	})
	addr := startTestServer(t, routes)

	c := New(Config{
		URL: "ldap://" + addr, BindDN: testBindDN, BindPassword: testBindPassword, InsecureSkipTLS: true,
		UserSearchBase: userSearchBase, UsernameAttribute: "uid",
	})

	members, err := c.GetGroupMembers(context.Background(), groupDN)
	if err != nil {
		t.Fatalf("GetGroupMembers() error = %v", err)
	}
	if len(members) != 2 || members[0] != "alice" || members[1] != "bob" {
		t.Fatalf("GetGroupMembers() = %v, want [alice bob]", members)
	}

	wantFilter := "(memberOf=" + groupDN + ")"
	if gotFilter != wantFilter {
		t.Fatalf("reverse query filter = %q, want %q", gotFilter, wantFilter)
	}
}

func TestClientGetGroupMembersFallsBackToMemberAttribute(t *testing.T) {
	const (
		userSearchBase = "ou=people,dc=corp,dc=local"
		groupDN        = "cn=data-team,ou=groups,dc=corp,dc=local"
		aliceDN        = "uid=alice," + userSearchBase
		bobDN          = "uid=bob," + userSearchBase
	)

	routes := ldapserver.NewRouteMux()
	routes.Bind(simpleBindHandler(testBindDN, testBindPassword))
	routes.Search(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		r := m.GetSearchRequest()
		base := string(r.BaseObject())
		switch {
		case int(r.Scope()) == ldap.ScopeBaseObject && base == groupDN:
			// No memberOf overlay: the group entry carries plain "member"
			// DNs instead, same as bare OpenLDAP.
			e := ldapserver.NewSearchResultEntry(groupDN)
			e.AddAttribute("member", aliceDN, bobDN)
			w.Write(e)
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
		case int(r.Scope()) == ldap.ScopeWholeSubtree && base == userSearchBase:
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
		case int(r.Scope()) == ldap.ScopeBaseObject && base == aliceDN:
			e := ldapserver.NewSearchResultEntry(aliceDN)
			e.AddAttribute("uid", "alice")
			w.Write(e)
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
		case int(r.Scope()) == ldap.ScopeBaseObject && base == bobDN:
			e := ldapserver.NewSearchResultEntry(bobDN)
			e.AddAttribute("uid", "bob")
			w.Write(e)
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
		default:
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultNoSuchObject))
		}
	})
	addr := startTestServer(t, routes)

	c := New(Config{
		URL: "ldap://" + addr, BindDN: testBindDN, BindPassword: testBindPassword, InsecureSkipTLS: true,
		UserSearchBase: userSearchBase, UsernameAttribute: "uid",
	})

	members, err := c.GetGroupMembers(context.Background(), groupDN)
	if err != nil {
		t.Fatalf("GetGroupMembers() error = %v", err)
	}
	if len(members) != 2 || members[0] != "alice" || members[1] != "bob" {
		t.Fatalf("GetGroupMembers() = %v, want [alice bob]", members)
	}
}

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: cert}
}

func startTLSHandler(serverCert tls.Certificate) ldapserver.HandlerFunc {
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultSuccess)
		res.SetResponseName(ldapserver.NoticeOfStartTLS)
		w.Write(res)

		tlsConn := tls.Server(m.Client.GetConn(), &tls.Config{Certificates: []tls.Certificate{serverCert}})
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		m.Client.SetConn(tlsConn)
	}
}

func TestClientStartTLSUpgradeSucceedsAgainstTrustedCA(t *testing.T) {
	serverCert := generateSelfSignedCert(t)

	routes := ldapserver.NewRouteMux()
	routes.Bind(simpleBindHandler(testBindDN, testBindPassword))
	routes.Extended(startTLSHandler(serverCert)).RequestName(ldapserver.NoticeOfStartTLS)
	addr := startTestServer(t, routes)

	pool := x509.NewCertPool()
	pool.AddCert(serverCert.Leaf)

	c := New(Config{
		URL: "ldap://" + addr, BindDN: testBindDN, BindPassword: testBindPassword,
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"},
	})

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() over StartTLS = %v, want nil", err)
	}
}

func TestClientStartTLSUpgradeFailsAgainstUntrustedCert(t *testing.T) {
	serverCert := generateSelfSignedCert(t)

	routes := ldapserver.NewRouteMux()
	routes.Bind(simpleBindHandler(testBindDN, testBindPassword))
	routes.Extended(startTLSHandler(serverCert)).RequestName(ldapserver.NoticeOfStartTLS)
	addr := startTestServer(t, routes)

	// No TLSConfig set: falls back to the system trust store, which has
	// never heard of this self-signed cert, so the handshake must fail.
	c := New(Config{URL: "ldap://" + addr, BindDN: testBindDN, BindPassword: testBindPassword})

	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected StartTLS to fail against an untrusted self-signed certificate")
	}
}
