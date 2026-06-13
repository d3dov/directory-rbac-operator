// Package metrics defines the Prometheus collectors the controllers report
// through, registered on controller-runtime's default registry so they're
// served on the same /metrics endpoint as everything else.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// SyncTotal counts reconciles by binding kind and outcome.
	SyncTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ldaprbac_sync_total",
		Help: "Total number of reconciles, by kind and result.",
	}, []string{"kind", "result"})

	// SyncDuration times a full reconcile call, by binding kind.
	SyncDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ldaprbac_sync_duration_seconds",
		Help:    "Duration of a single reconcile, by kind.",
		Buckets: prometheus.DefBuckets,
	}, []string{"kind"})

	// LDAPErrorsTotal counts reconciles that ended Degraded, by provider.
	// Not perfectly precise - a handful of markDegraded causes are k8s API
	// errors rather than directory errors (e.g. a missing LDAPProvider
	// reference) - but the overwhelming majority are dial/bind/search
	// failures, and splitting those out isn't worth the extra bookkeeping.
	LDAPErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ldaprbac_ldap_errors_total",
		Help: "Total number of reconciles that failed against the directory, by provider.",
	}, []string{"provider"})

	// MembersCount reports the last successfully resolved member count for
	// a binding. Cardinality is bounded by the number of binding objects,
	// not their membership size.
	MembersCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ldaprbac_members_count",
		Help: "Number of members last resolved for a binding.",
	}, []string{"kind", "namespace", "name"})
)

func init() {
	metrics.Registry.MustRegister(SyncTotal, SyncDuration, LDAPErrorsTotal, MembersCount)
}
