// Package ldapclient resolves LDAP/Active Directory group membership for use
// as RBAC subjects.
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
