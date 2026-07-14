package ldapclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/time/rate"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// DefaultPageSize is the RFC 2696 simple paged results page size requested
// for the reverse membership query. It matches Active Directory's own
// default MaxPageSize, which is also the size at which an unpaged search
// against AD silently truncates - a group with more members than this
// simply lost the rest with no error, before paging was requested at all.
// Paging is requested unconditionally rather than only for
// DirectoryTypeActiveDirectory: RFC 2696 is a generic LDAP control that
// OpenLDAP and 389-ds also implement, and a server that doesn't recognize it
// just returns a normal, single, capped response - identical to the
// pre-paging behavior - so there is no backend-specific case to gate here.
const DefaultPageSize uint32 = 1000

// ldapConn is the subset of *ldap.Conn that Client's query helpers use.
// Extracting it lets paging and referral-handling behavior be verified
// against a fake: the vjeantet/ldapserver instance used by the wire tests
// elsewhere in this package doesn't parse or emit LDAP controls at all, so
// it cannot simulate an RFC 2696 paged response.
type ldapConn interface {
	Bind(username, password string) error
	StartTLS(config *tls.Config) error
	SetTimeout(timeout time.Duration)
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
	Close() error
}

var _ ldapConn = (*ldap.Conn)(nil)

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

	// PageSize overrides DefaultPageSize for the reverse membership query's
	// RFC 2696 paging control. Zero means DefaultPageSize; there is
	// currently no LDAPProviderSpec field surfacing this, since the default
	// already matches what it's chosen to match (AD's own MaxPageSize) and
	// nothing has yet needed to tune it per provider.
	PageSize uint32

	// Limiter, if set, is waited on before every dial - shared across every
	// Client built for the same provider (see Limiters), so the request
	// budget is enforced per directory, not per Client instance.
	Limiter *rate.Limiter
}

func (c *Client) pageSize() uint32 {
	if c.cfg.PageSize == 0 {
		return DefaultPageSize
	}
	return c.cfg.PageSize
}

// Client resolves group membership by dialing, binding and querying fresh on
// every call. Reconcile cadence is typically minutes, making per-call
// connection cost negligible, whereas LDAP connections aren't reliably
// shareable across concurrent callers and idle ones are routinely killed by
// firewalls/load balancers - so pooling is intentionally not attempted here.
type Client struct {
	cfg Config
}

var (
	_ Grouper = (*Client)(nil)
	_ Pinger  = (*Client)(nil)
)

// New returns a Client configured against a single LDAPProvider.
func New(cfg Config) *Client {
	return &Client{cfg: cfg}
}

// Ping verifies the directory is reachable and the configured bind
// credentials are accepted, without resolving any group membership. It backs
// the LDAPProvider health check, which needs a signal independent of any
// particular binding's groupDN.
func (c *Client) Ping(ctx context.Context) error {
	conn, err := c.connectAndBind(ctx)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func (c *Client) connectAndBind(ctx context.Context) (*ldap.Conn, error) {
	if c.cfg.Limiter != nil {
		if err := c.cfg.Limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("ldapclient: rate limit: %w", err)
		}
	}

	conn, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("ldapclient: dial: %w", err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetTimeout(time.Until(deadline))
	}

	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ldapclient: bind: %w", err)
	}
	return conn, nil
}

// GetGroupMembers resolves groupDN's membership, projected through
// UsernameAttribute and sorted.
func (c *Client) GetGroupMembers(ctx context.Context, groupDN string) ([]string, error) {
	conn, err := c.connectAndBind(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	groupEntry, err := c.lookupGroup(ctx, conn, groupDN)
	if err != nil {
		return nil, err
	}

	members, err := c.resolveMembers(ctx, conn, groupDN, groupEntry)
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
			_ = conn.Close()
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
func (c *Client) lookupGroup(ctx context.Context, conn ldapConn, groupDN string) (*ldap.Entry, error) {
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
		if ldap.IsErrorWithCode(err, ldap.LDAPResultReferral) {
			logReferralChasingSkipped(ctx, "group lookup", groupDN)
			return nil, fmt.Errorf("ldapclient: lookup group %s: directory returned a referral instead of a result, and referral chasing is not implemented: %w", groupDN, err)
		}
		return nil, fmt.Errorf("ldapclient: lookup group %s: %w", groupDN, err)
	}
	logReferrals(ctx, "group lookup", groupDN, result.Referrals)
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
//
// The reverse query is the one search in this file that can plausibly
// return more entries than a server's unpaged response cap, so it's the
// only one issued via SearchWithPaging rather than Search.
func (c *Client) resolveMembers(ctx context.Context, conn ldapConn, groupDN string, groupEntry *ldap.Entry) ([]string, error) {
	filter := fmt.Sprintf("(memberOf=%s)", ldap.EscapeFilter(groupDN))
	req := ldap.NewSearchRequest(
		c.cfg.UserSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{c.cfg.UsernameAttribute},
		nil,
	)

	result, err := conn.SearchWithPaging(req, c.pageSize())
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultReferral) {
			logReferralChasingSkipped(ctx, "reverse membership query", groupDN)
		}
		return nil, fmt.Errorf("query members via memberOf: %w", err)
	}
	logReferrals(ctx, "reverse membership query", groupDN, result.Referrals)
	if len(result.Entries) > 0 {
		return usernames(result.Entries, c.cfg.UsernameAttribute), nil
	}

	// memberDNs, not memberDNS: revive's initialism convention would read as
	// the Domain Name System here, which isn't what this is.
	memberDNs := groupEntry.GetAttributeValues("member") //nolint:revive // see comment above
	if len(memberDNs) == 0 {
		memberDNs = groupEntry.GetAttributeValues("uniqueMember")
	}

	members := make([]string, 0, len(memberDNs))
	for _, dn := range memberDNs {
		username, err := c.lookupUsername(ctx, conn, dn)
		if err != nil {
			return nil, fmt.Errorf("resolve member %q: %w", dn, err)
		}
		if username != "" {
			members = append(members, username)
		}
	}
	return members, nil
}

func (c *Client) lookupUsername(ctx context.Context, conn ldapConn, dn string) (string, error) {
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
		if ldap.IsErrorWithCode(err, ldap.LDAPResultReferral) {
			// The member DN lives in a naming context this connection
			// wasn't pointed at (e.g. another domain in an AD forest).
			// Chasing it isn't implemented, so it's skipped like a stale
			// DN rather than failing the whole group's sync over one
			// member.
			logReferralChasingSkipped(ctx, "member lookup", dn)
			return "", nil
		}
		return "", err
	}
	logReferrals(ctx, "member lookup", dn, result.Referrals)
	if len(result.Entries) == 0 {
		return "", nil
	}
	return result.Entries[0].GetAttributeValue(c.cfg.UsernameAttribute), nil
}

// logReferrals surfaces continuation references returned alongside an
// otherwise-successful result (as opposed to a response that is itself a
// referral - see logReferralChasingSkipped). Silently dropping these would
// make a group's membership look smaller than it is - e.g. in a multi-domain
// AD forest, where part of a group's membership can live in another domain -
// with nothing in the logs to explain why.
func logReferrals(ctx context.Context, operation, subjectDN string, referrals []string) {
	if len(referrals) == 0 {
		return
	}
	logf.FromContext(ctx).Info("directory returned referrals that will not be followed",
		"operation", operation, "dn", subjectDN, "referrals", referrals)
}

// logReferralChasingSkipped logs the explicit decision not to follow a
// referral the directory returned in place of a result. Chasing it would
// mean opening a connection to a server address supplied by the directory
// at runtime, one this operator has no configured credentials or TLS trust
// for - treated here as a deliberate non-goal rather than a gap to silently
// paper over.
func logReferralChasingSkipped(ctx context.Context, operation, subjectDN string) {
	logf.FromContext(ctx).Info("directory returned a referral instead of a result; referral chasing is not implemented",
		"operation", operation, "dn", subjectDN)
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
