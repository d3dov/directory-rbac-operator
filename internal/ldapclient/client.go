package ldapclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config holds everything needed to open a connection and resolve group
// membership against a single LDAPProvider.
type Config struct {
	URL          string
	BindDN       string
	BindPassword string

	// InsecureSkipTLS allows a plaintext bind with no StartTLS upgrade for
	// ldap:// URLs. Ignored for ldaps:// (already TLS).
	InsecureSkipTLS bool

	// TLSConfig customizes CA validation for ldaps:// and StartTLS. Nil
	// falls back to the system trust store.
	TLSConfig *tls.Config

	UserSearchBase    string
	GroupSearchBase   string
	UsernameAttribute string
}

// Client resolves group membership by dialing, binding and querying fresh on
// every call. Reconcile cadence is typically minutes, making per-call
// connection cost negligible, whereas LDAP connections aren't reliably
// shareable across concurrent callers and idle ones are routinely killed by
// firewalls/load balancers - so pooling is intentionally not attempted here.
type Client struct {
	cfg Config
}

var _ Grouper = (*Client)(nil)

func New(cfg Config) *Client {
	return &Client{cfg: cfg}
}

func (c *Client) GetGroupMembers(ctx context.Context, groupDN string) ([]string, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("ldapclient: dial: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetTimeout(time.Until(deadline))
	}

	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldapclient: bind: %w", err)
	}

	groupEntry, err := c.lookupGroup(conn, groupDN)
	if err != nil {
		return nil, err
	}

	members, err := c.resolveMembers(conn, groupDN, groupEntry)
	if err != nil {
		return nil, fmt.Errorf("ldapclient: resolve members for %s: %w", groupDN, err)
	}

	sort.Strings(members)
	return members, nil
}

func (c *Client) dial() (*ldap.Conn, error) {
	isLDAPS := strings.HasPrefix(c.cfg.URL, "ldaps://")

	var dialOpts []ldap.DialOpt
	if isLDAPS {
		dialOpts = append(dialOpts, ldap.DialWithTLSConfig(c.tlsConfig()))
	}

	conn, err := ldap.DialURL(c.cfg.URL, dialOpts...)
	if err != nil {
		return nil, err
	}

	if !isLDAPS && !c.cfg.InsecureSkipTLS {
		if err := conn.StartTLS(c.tlsConfig()); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}

	return conn, nil
}

func (c *Client) tlsConfig() *tls.Config {
	if c.cfg.TLSConfig != nil {
		return c.cfg.TLSConfig
	}
	return &tls.Config{}
}

// lookupGroup confirms groupDN exists and returns its entry, fetching the
// member/uniqueMember attributes needed by the fallback path in
// resolveMembers.
func (c *Client) lookupGroup(conn *ldap.Conn, groupDN string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"member", "uniqueMember"},
		nil,
	)

	result, err := conn.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, fmt.Errorf("ldapclient: %w: %s", ErrGroupNotFound, groupDN)
		}
		return nil, fmt.Errorf("ldapclient: lookup group %s: %w", groupDN, err)
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("ldapclient: %w: %s", ErrGroupNotFound, groupDN)
	}
	return result.Entries[0], nil
}

// resolveMembers prefers a single reverse query - search UserSearchBase for
// (memberOf=groupDN) - over reading the group's member DN list and looking
// each one up individually. Directories without a memberOf overlay (plain
// OpenLDAP) never match that filter even for non-empty groups, so a group
// with no reverse-query hits falls back to resolving its own
// member/uniqueMember attribute instead.
func (c *Client) resolveMembers(conn *ldap.Conn, groupDN string, groupEntry *ldap.Entry) ([]string, error) {
	filter := fmt.Sprintf("(memberOf=%s)", ldap.EscapeFilter(groupDN))
	req := ldap.NewSearchRequest(
		c.cfg.UserSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{c.cfg.UsernameAttribute},
		nil,
	)

	result, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("query members via memberOf: %w", err)
	}
	if len(result.Entries) > 0 {
		return usernames(result.Entries, c.cfg.UsernameAttribute), nil
	}

	memberDNs := groupEntry.GetAttributeValues("member")
	if len(memberDNs) == 0 {
		memberDNs = groupEntry.GetAttributeValues("uniqueMember")
	}

	members := make([]string, 0, len(memberDNs))
	for _, dn := range memberDNs {
		username, err := c.lookupUsername(conn, dn)
		if err != nil {
			return nil, fmt.Errorf("resolve member %q: %w", dn, err)
		}
		if username != "" {
			members = append(members, username)
		}
	}
	return members, nil
}

func (c *Client) lookupUsername(conn *ldap.Conn, dn string) (string, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{c.cfg.UsernameAttribute},
		nil,
	)

	result, err := conn.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			// Stale member DN (e.g. deleted user still listed on the
			// group); skip it rather than fail the whole sync.
			return "", nil
		}
		return "", err
	}
	if len(result.Entries) == 0 {
		return "", nil
	}
	return result.Entries[0].GetAttributeValue(c.cfg.UsernameAttribute), nil
}

func usernames(entries []*ldap.Entry, attr string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if v := e.GetAttributeValue(attr); v != "" {
			out = append(out, v)
		}
	}
	return out
}
