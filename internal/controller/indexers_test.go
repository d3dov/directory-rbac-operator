package controller

import (
	"context"
	"errors"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// countingFieldIndexer fails IndexField on the failAt'th call (1-based),
// letting SetupIndexers' three early-return branches be exercised
// individually without spinning up a real cache.
type countingFieldIndexer struct {
	calls  int
	failAt int
}

func (c *countingFieldIndexer) IndexField(context.Context, client.Object, string, client.IndexerFunc) error {
	c.calls++
	if c.calls == c.failAt {
		return errors.New("boom")
	}
	return nil
}

type fakeIndexerManager struct{ indexer client.FieldIndexer }

func (m *fakeIndexerManager) GetFieldIndexer() client.FieldIndexer { return m.indexer }

func TestSetupIndexersPropagatesEachRegistrationFailure(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		mgr := &fakeIndexerManager{indexer: &countingFieldIndexer{failAt: failAt}}
		if err := SetupIndexers(context.Background(), mgr); err == nil {
			t.Fatalf("SetupIndexers() error = nil, want an error when registration %d fails", failAt)
		}
	}
}

func TestSetupIndexersSucceedsWhenAllRegistrationsSucceed(t *testing.T) {
	mgr := &fakeIndexerManager{indexer: &countingFieldIndexer{failAt: -1}}
	if err := SetupIndexers(context.Background(), mgr); err != nil {
		t.Fatalf("SetupIndexers() error = %v, want nil", err)
	}
}
