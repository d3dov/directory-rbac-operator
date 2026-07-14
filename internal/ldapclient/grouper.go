// Package ldapclient resolves LDAP/Active Directory group membership for use
// as RBAC subjects.
//
// Config.DirectoryType switches the handful of places query behavior
// actually differs between backends, explicitly rather than by inferring it
// from other settings or by probing server capabilities at runtime:
//
//   - OpenLDAP (the zero value): a plain memberOf equality filter for the
//     reverse membership query. A group with no memberOf overlay configured
//     falls back to reading the group entry's own member/uniqueMember
//     attribute instead (see resolveMembers) - this fallback isn't
//     directoryType-gated either, since it's really "does this particular
//     server have the overlay," not a backend family distinction.
//   - ActiveDirectory: the same reverse query, but with Microsoft's
//     LDAP_MATCHING_RULE_IN_CHAIN OID applied to memberOf (see
//     MatchingRuleInChainOID), so nested group membership resolves
//     server-side instead of requiring the client to walk the group tree.
//   - FreeIPA: identical to OpenLDAP's plain filter. FreeIPA's underlying
//     389-ds server computes memberOf recursively itself (the MemberOf
//     plugin walks nested groups at write time, not read time), so a
//     group's memberOf-based membership is already flattened by the time
//     it reaches this client. There is no separate recursive-query path to
//     write for FreeIPA, and applying AD's matching rule against a server
//     that doesn't index it would be a filter it can't optimize at best.
//
// RFC 2696 paged results (see DefaultPageSize) and referral handling (see
// logReferrals) are not gated by DirectoryType at all: both are generic
// LDAP behaviors that OpenLDAP and 389-ds implement the same way AD does.
package ldapclient

import (
	"context"
	"errors"
)

// Grouper resolves a group DN into member subject names, already projected
// through the provider's configured username attribute so callers can use
// the result directly as an rbacv1.Subject name (Kind=User). Implementations
// must be safe for concurrent use.
type Grouper interface {
	GetGroupMembers(ctx context.Context, groupDN string) ([]string, error)
}

// Pinger verifies directory connectivity and bind credentials without
// resolving any particular group. LDAPProvider's own health check uses this
// instead of Grouper, since it has no groupDN to query.
type Pinger interface {
	Ping(ctx context.Context) error
}

// ErrGroupNotFound distinguishes a confirmed-absent group DN from any other
// error (connectivity, auth, malformed filter, ...). Callers check it with
// errors.Is to decide between the GroupNotFound and Degraded status
// conditions; every other error is treated as Degraded.
var ErrGroupNotFound = errors.New("ldapclient: group not found")
