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
}

var _ ldapclient.Grouper = (*Grouper)(nil)

func (g *Grouper) GetGroupMembers(_ context.Context, groupDN string) ([]string, error) {
	members, ok := g.Groups[groupDN]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ldapclient.ErrGroupNotFound, groupDN)
	}
	return members, nil
}
