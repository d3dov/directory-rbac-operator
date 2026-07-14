// Package fake provides an in-memory ldapclient.Grouper for tests, so
// controller and rbacsync tests don't need a real (or embedded) directory
// server.
package fake

import (
	"context"
	"fmt"

	"github.com/denis-da-engineer/directory-rbac-operator/internal/ldapclient"
)

// Grouper serves membership from an in-memory map keyed by group DN.
type Grouper struct {
	Groups map[string][]string

	// Errors, if set, returns a specific error for a groupDN instead of
	// consulting Groups - simulating a directory failure other than a
	// confirmed-absent group (which is what a Groups miss already means).
	Errors map[string]error
}

var _ ldapclient.Grouper = (*Grouper)(nil)

// GetGroupMembers returns the members registered for groupDN in Groups, the
// matching entry in Errors if one is set, or ldapclient.ErrGroupNotFound if
// groupDN has neither.
func (g *Grouper) GetGroupMembers(_ context.Context, groupDN string) ([]string, error) {
	if err, ok := g.Errors[groupDN]; ok {
		return nil, err
	}
	members, ok := g.Groups[groupDN]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ldapclient.ErrGroupNotFound, groupDN)
	}
	return members, nil
}
