package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	ldaprbacv1alpha1 "github.com/d3dov/directory-rbac-operator/api/v1alpha1"
	"github.com/d3dov/directory-rbac-operator/internal/ldapclient"
	"github.com/d3dov/directory-rbac-operator/internal/metrics"
)

const ldapProviderKind = "LDAPProvider"

// inUseProtectionFinalizer blocks LDAPProvider deletion while any binding
// still references it, so removing a provider can never orphan bindings
// into a permanently Degraded state.
const inUseProtectionFinalizer = "ldaprbac.io/in-use-protection"

// inUseRecheckInterval governs how quickly a blocked deletion notices its
// last dependent binding disappearing. LDAPProviderReconciler doesn't watch
// binding objects directly, so this polls the provider-ref index instead of
// adding another watch/mapper pair for what is a rare, non-latency-sensitive
// path. Var rather than const so tests can shorten it.
var inUseRecheckInterval = 30 * time.Second

// LDAPProviderReconciler runs a bind-only health check against the
// directory a LDAPProvider describes; it does not itself touch any RBAC
// object.
type LDAPProviderReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Pinger   PingerResolver
	Recorder events.EventRecorder

	// Limiters is the same registry GrouperFactory draws rate limiters from;
	// finalize() deletes a provider's entry once it's actually gone, so a
	// long-running operator doesn't accumulate one stale limiter per
	// deleted provider. Nil is fine (no-op) if rate limiting is disabled.
	Limiters *ldapclient.Limiters
}

// +kubebuilder:rbac:groups=ldaprbac.io,resources=ldapproviders,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=ldaprbac.io,resources=ldapproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ldaprbac.io,resources=ldapproviders/finalizers,verbs=update

// Reconcile runs the bind-only health check described on
// LDAPProviderReconciler, and handles the in-use-protection finalizer.
func (r *LDAPProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	defer func() {
		metrics.SyncDuration.WithLabelValues(ldapProviderKind).Observe(time.Since(start).Seconds())
	}()

	log := logf.FromContext(ctx)

	var provider ldaprbacv1alpha1.LDAPProvider
	if err := r.Get(ctx, req.NamespacedName, &provider); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !provider.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &provider)
	}

	if !controllerutil.ContainsFinalizer(&provider, inUseProtectionFinalizer) {
		controllerutil.AddFinalizer(&provider, inUseProtectionFinalizer)
		if err := r.Update(ctx, &provider); err != nil {
			return ctrl.Result{}, err
		}
	}

	if provider.Spec.InsecureSkipTLS {
		log.Info("provider allows insecureSkipTLS: binding in plaintext, no transport security is applied")
	}

	if err := validateTLSConfig(&provider.Spec); err != nil {
		return r.markInvalidSpec(ctx, &provider, err)
	}

	pinger, err := r.Pinger.Pinger(ctx, &provider)
	if err != nil {
		return r.markDegraded(ctx, &provider, err)
	}

	if err := pinger.Ping(ctx); err != nil {
		return r.markDegraded(ctx, &provider, err)
	}

	return r.markReady(ctx, &provider)
}

// validateTLSConfig enforces that an ldap:// URL makes an explicit transport
// security choice instead of silently falling back to something the operator
// picked implicitly:
//   - ldaps:// is always implicit TLS, regardless of insecureSkipTLS/tlsConfig.
//   - ldap:// + insecureSkipTLS: true is explicit plaintext.
//   - ldap:// + tlsConfig.caSecretRef set upgrades via StartTLS against that CA.
//   - ldap:// with neither is rejected: it would otherwise silently negotiate
//     StartTLS against the system trust store, which is easy to mistake for a
//     secure default against an internal CA that isn't actually trusted.
func validateTLSConfig(spec *ldaprbacv1alpha1.LDAPProviderSpec) error {
	if strings.HasPrefix(spec.URL, "ldaps://") {
		return nil
	}
	if spec.InsecureSkipTLS {
		return nil
	}
	if spec.TLSConfig != nil && spec.TLSConfig.CASecretRef != nil {
		return nil
	}
	return fmt.Errorf("ldap:// requires either tlsConfig.caSecretRef (for StartTLS) or insecureSkipTLS: true")
}

func (r *LDAPProviderReconciler) finalize(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(provider, inUseProtectionFinalizer) {
		return ctrl.Result{}, nil
	}

	inUse, err := r.hasDependents(ctx, provider)
	if err != nil {
		return ctrl.Result{}, err
	}
	if inUse {
		logf.FromContext(ctx).Info("deletion blocked: bindings still reference this provider")
		recordWarning(r.Recorder, provider, "DeletionBlocked", "bindings still reference this provider")
		return ctrl.Result{RequeueAfter: inUseRecheckInterval}, nil
	}

	if r.Limiters != nil {
		r.Limiters.Delete(provider.Name)
	}

	controllerutil.RemoveFinalizer(provider, inUseProtectionFinalizer)
	return ctrl.Result{}, r.Update(ctx, provider)
}

func (r *LDAPProviderReconciler) hasDependents(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (bool, error) {
	var bindings ldaprbacv1alpha1.RBACGroupBindingList
	if err := r.List(ctx, &bindings, client.MatchingFields{providerRefIndexField: provider.Name}, client.Limit(1)); err != nil {
		return false, err
	}
	if len(bindings.Items) > 0 {
		return true, nil
	}

	var clusterBindings ldaprbacv1alpha1.ClusterRBACGroupBindingList
	if err := r.List(ctx, &clusterBindings, client.MatchingFields{providerRefIndexField: provider.Name}, client.Limit(1)); err != nil {
		return false, err
	}
	return len(clusterBindings.Items) > 0, nil
}

func (r *LDAPProviderReconciler) markReady(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (ctrl.Result, error) {
	metrics.SyncTotal.WithLabelValues(ldapProviderKind, "ready").Inc()

	provider.Status.ObservedGeneration = provider.Generation
	now := metav1.Now()
	provider.Status.LastVerifiedTime = &now

	meta.SetStatusCondition(&provider.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionReady, Status: metav1.ConditionTrue,
		Reason: ldaprbacv1alpha1.ReasonSyncSucceeded, Message: "bind succeeded",
	})
	meta.SetStatusCondition(&provider.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionDegraded, Status: metav1.ConditionFalse,
		Reason: ldaprbacv1alpha1.ReasonSyncSucceeded,
	})

	if err := r.Status().Update(ctx, provider); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: provider.Spec.SyncInterval.Duration}, nil
}

// markDegraded's ctrl.Result is always the zero value: it deliberately
// mirrors Reconcile's return shape so call sites can `return
// r.markDegraded(...)` directly, rather than returning just an error and
// making every caller wrap it back into a ctrl.Result.
//
//nolint:unparam // see comment above
func (r *LDAPProviderReconciler) markDegraded(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider, cause error) (ctrl.Result, error) {
	recordWarning(r.Recorder, provider, "BindFailed", cause.Error())
	metrics.SyncTotal.WithLabelValues(ldapProviderKind, "degraded").Inc()
	metrics.LDAPErrorsTotal.WithLabelValues(provider.Name).Inc()

	provider.Status.ObservedGeneration = provider.Generation

	meta.SetStatusCondition(&provider.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionReady, Status: metav1.ConditionFalse,
		Reason: ldaprbacv1alpha1.ReasonLDAPUnreachable, Message: cause.Error(),
	})
	meta.SetStatusCondition(&provider.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionDegraded, Status: metav1.ConditionTrue,
		Reason: ldaprbacv1alpha1.ReasonLDAPUnreachable, Message: cause.Error(),
	})

	if err := r.Status().Update(ctx, provider); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, cause
}

// markInvalidSpec doesn't requeue: nothing will change until the user edits
// the spec, and that edit itself triggers a new reconcile. Its ctrl.Result is
// always the zero value, for the same reason markDegraded's is.
//
//nolint:unparam // see markDegraded
func (r *LDAPProviderReconciler) markInvalidSpec(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider, cause error) (ctrl.Result, error) {
	recordWarning(r.Recorder, provider, "InvalidSpec", cause.Error())
	metrics.SyncTotal.WithLabelValues(ldapProviderKind, "invalid_spec").Inc()

	provider.Status.ObservedGeneration = provider.Generation

	meta.SetStatusCondition(&provider.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionReady, Status: metav1.ConditionFalse,
		Reason: ldaprbacv1alpha1.ReasonInvalidSpec, Message: cause.Error(),
	})

	return ctrl.Result{}, r.Status().Update(ctx, provider)
}

// SetupWithManager wires the reconciler into mgr.
func (r *LDAPProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ldaprbacv1alpha1.LDAPProvider{}).
		Complete(r)
}
