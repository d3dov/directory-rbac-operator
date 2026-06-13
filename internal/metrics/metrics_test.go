package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCollectorsRecordValues(t *testing.T) {
	SyncTotal.Reset()
	SyncTotal.WithLabelValues("RBACGroupBinding", "ready").Inc()
	if got := testutil.ToFloat64(SyncTotal.WithLabelValues("RBACGroupBinding", "ready")); got != 1 {
		t.Fatalf("SyncTotal = %v, want 1", got)
	}

	MembersCount.Reset()
	MembersCount.WithLabelValues("RBACGroupBinding", "data-platform", "data-team-edit").Set(3)
	if got := testutil.ToFloat64(MembersCount.WithLabelValues("RBACGroupBinding", "data-platform", "data-team-edit")); got != 3 {
		t.Fatalf("MembersCount = %v, want 3", got)
	}

	LDAPErrorsTotal.Reset()
	LDAPErrorsTotal.WithLabelValues("corp-ad").Inc()
	LDAPErrorsTotal.WithLabelValues("corp-ad").Inc()
	if got := testutil.ToFloat64(LDAPErrorsTotal.WithLabelValues("corp-ad")); got != 2 {
		t.Fatalf("LDAPErrorsTotal = %v, want 2", got)
	}
}
