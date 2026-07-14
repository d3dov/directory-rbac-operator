package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
	"github.com/denis-da-engineer/directory-rbac-operator/internal/ldapclient"
	"github.com/denis-da-engineer/directory-rbac-operator/internal/metrics"
	"github.com/denis-da-engineer/directory-rbac-operator/internal/rbacsync"
)

const rbacGroupBindingKind = "RBACGroupBinding"

// RBACGroupBindingReconciler syncs a namespaced RoleBinding's subjects to an
// LDAP/AD group's membership.
type RBACGroupBindingReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Grouper  GrouperResolver
	Recorder events.EventRecorder

	// SecretNamespace scopes the Secret-rotation watch below to the same
	// namespace GrouperFactory reads bind passwords/CA bundles from -
	// without it every Secret write cluster-wide would trigger a List
	// against the provider index for no reason.
	SecretNamespace string
}

// syncOutcome distinguishes what reconcileRoleBinding actually did, so the
// caller can emit an Event only when something changed rather than on every
// no-op reconcile.
type syncOutcome int

const (
	syncUnchanged syncOutcome = iota
	syncCreated
	syncUpdated
	syncRecreated
)

// +kubebuilder:rbac:groups=ldaprbac.io,resources=rbacgroupbindings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=ldaprbac.io,resources=rbacgroupbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ldaprbac.io,resources=ldapproviders,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete
//
// The API server refuses to create/update a RoleBinding that grants
// permissions the requester doesn't itself hold, unless the requester also
// has "bind" on the referenced Role/ClusterRole - so binding roleRef.name to
// arbitrary roles requires this regardless of scope. There's no way to
// scope it to "only roles some future RBACGroupBinding references" ahead of
// time; see the README security notes for the trade-off this implies.
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;clusterroles,verbs=bind

// Reconcile mirrors ClusterRBACGroupBindingReconciler.Reconcile closely
// enough that dupl flags it; unifying the two via generics/interfaces would
// trade a small amount of duplication for a layer of indirection between two
// concrete, differently-scoped Kubernetes object types (RoleBinding vs
// ClusterRoleBinding, namespaced vs cluster CRs) - not a clear improvement,
// and kubebuilder itself scaffolds separate reconcilers for exactly this
// kind of pair.
//
//nolint:dupl // see comment above
func (r *RBACGroupBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	defer func() {
		metrics.SyncDuration.WithLabelValues(rbacGroupBindingKind).Observe(time.Since(start).Seconds())
	}()

	log := logf.FromContext(ctx)

	var binding ldaprbacv1alpha1.RBACGroupBinding
	if err := r.Get(ctx, req.NamespacedName, &binding); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log = log.WithValues("provider", binding.Spec.ProviderRef, "groupDN", binding.Spec.GroupDN)

	var provider ldaprbacv1alpha1.LDAPProvider
	if err := r.Get(ctx, client.ObjectKey{Name: binding.Spec.ProviderRef}, &provider); err != nil {
		if apierrors.IsNotFound(err) {
			return r.markDegraded(ctx, &binding, fmt.Errorf("LDAPProvider %q not found", binding.Spec.ProviderRef))
		}
		return ctrl.Result{}, err
	}

	grouper, err := r.Grouper.Grouper(ctx, &provider)
	if err != nil {
		return r.markDegraded(ctx, &binding, err)
	}

	members, err := grouper.GetGroupMembers(ctx, binding.Spec.GroupDN)
	switch {
	case errors.Is(err, ldapclient.ErrGroupNotFound):
		log.Info("group not found in directory")
		return r.markGroupNotFound(ctx, &binding, provider.Spec.SyncInterval.Duration)
	case err != nil:
		return r.markDegraded(ctx, &binding, err)
	}

	desired := rbacsync.BuildRoleBinding(&binding, members)
	if err := controllerutil.SetControllerReference(&binding, desired, r.Scheme); err != nil {
		return ctrl.Result{}, err
	}

	outcome, err := r.reconcileRoleBinding(ctx, desired)
	if err != nil {
		return r.markDegraded(ctx, &binding, err)
	}

	switch outcome {
	case syncUnchanged:
		// nothing changed; no event to record.
	case syncCreated:
		recordSuccessf(r.Recorder, &binding, "RoleBindingCreated", "created RoleBinding %s with %d member(s)", desired.Name, len(members))
	case syncUpdated:
		recordSuccessf(r.Recorder, &binding, "RoleBindingUpdated", "updated RoleBinding %s to %d member(s)", desired.Name, len(members))
	case syncRecreated:
		recordSuccessf(r.Recorder, &binding, "RoleBindingRecreated", "recreated RoleBinding %s (roleRef changed)", desired.Name)
	}

	log.Info("synced group membership", "members", len(members))
	return r.markReady(ctx, &binding, members, provider.Spec.SyncInterval.Duration)
}

func (r *RBACGroupBindingReconciler) reconcileRoleBinding(ctx context.Context, desired *rbacv1.RoleBinding) (syncOutcome, error) {
	var existing rbacv1.RoleBinding
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return syncUnchanged, err
		}
		return syncCreated, nil
	case err != nil:
		return syncUnchanged, err
	}

	if existing.RoleRef != desired.RoleRef {
		// RoleRef is immutable on an existing RoleBinding (the API server
		// rejects updates that change it), so a spec.roleRef edit is
		// applied by deleting and recreating rather than updating.
		if err := r.Delete(ctx, &existing); err != nil {
			return syncUnchanged, err
		}
		if err := r.Create(ctx, desired); err != nil {
			return syncUnchanged, err
		}
		return syncRecreated, nil
	}

	// OwnerReferences is checked alongside Subjects (not just at Create
	// time) because without a garbage collector guaranteeing a same-named
	// prior object is gone first, "existing" could be a leftover RoleBinding
	// from a different, already-deleted binding of the same name - blindly
	// patching only Subjects would leave it adopted under a stale owner.
	if rbacsync.SubjectsEqual(existing.Subjects, desired.Subjects) && apiequality.Semantic.DeepEqual(existing.OwnerReferences, desired.OwnerReferences) {
		return syncUnchanged, nil
	}

	existing.Subjects = desired.Subjects
	existing.OwnerReferences = desired.OwnerReferences
	if err := r.Update(ctx, &existing); err != nil {
		return syncUnchanged, err
	}
	return syncUpdated, nil
}

func (r *RBACGroupBindingReconciler) markReady(ctx context.Context, binding *ldaprbacv1alpha1.RBACGroupBinding, members []string, interval time.Duration) (ctrl.Result, error) {
	preview, truncated := rbacsync.PreviewMembers(members)

	binding.Status.ObservedGeneration = binding.Generation
	now := metav1.Now()
	binding.Status.LastSyncTime = &now
	binding.Status.MemberCount = rbacsync.MemberCount(members)
	binding.Status.MembersPreview = preview
	binding.Status.MembersTruncated = truncated
	binding.Status.MembersHash = rbacsync.MembersHash(members)
	binding.Status.RoleBindingRef = &corev1.LocalObjectReference{Name: binding.Name}

	metrics.SyncTotal.WithLabelValues(rbacGroupBindingKind, "ready").Inc()
	metrics.MembersCount.WithLabelValues(rbacGroupBindingKind, binding.Namespace, binding.Name).Set(float64(len(members)))

	meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionReady, Status: metav1.ConditionTrue,
		Reason: ldaprbacv1alpha1.ReasonSyncSucceeded, Message: fmt.Sprintf("synced %d member(s)", len(members)),
	})
	meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionDegraded, Status: metav1.ConditionFalse,
		Reason: ldaprbacv1alpha1.ReasonSyncSucceeded,
	})
	meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionGroupNotFound, Status: metav1.ConditionFalse,
		Reason: ldaprbacv1alpha1.ReasonSyncSucceeded,
	})

	if err := r.Status().Update(ctx, binding); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// markDegraded leaves MemberCount/MembersPreview/MembersHash and the managed
// RoleBinding untouched - the fail-safe contract is that an unreachable
// directory or transient error never removes existing access, it only
// surfaces as a status condition. The error is returned so the workqueue's
// default exponential-backoff rate limiter governs the retry, rather than a
// hand-rolled backoff here. Its ctrl.Result is always the zero value,
// deliberately mirroring Reconcile's return shape so callers can `return
// r.markDegraded(...)` directly. It and markGroupNotFound below mirror
// ClusterRBACGroupBindingReconciler's; see the Reconcile comment above for
// why that's left as-is rather than unified.
//
//nolint:dupl,unparam // see comment above
func (r *RBACGroupBindingReconciler) markDegraded(ctx context.Context, binding *ldaprbacv1alpha1.RBACGroupBinding, cause error) (ctrl.Result, error) {
	recordWarning(r.Recorder, binding, "SyncFailed", cause.Error())
	metrics.SyncTotal.WithLabelValues(rbacGroupBindingKind, "degraded").Inc()
	metrics.LDAPErrorsTotal.WithLabelValues(binding.Spec.ProviderRef).Inc()

	binding.Status.ObservedGeneration = binding.Generation

	meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionReady, Status: metav1.ConditionFalse,
		Reason: ldaprbacv1alpha1.ReasonLDAPUnreachable, Message: cause.Error(),
	})
	meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionDegraded, Status: metav1.ConditionTrue,
		Reason: ldaprbacv1alpha1.ReasonLDAPUnreachable, Message: cause.Error(),
	})
	meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionGroupNotFound, Status: metav1.ConditionFalse,
		Reason: ldaprbacv1alpha1.ReasonLDAPUnreachable,
	})

	if err := r.Status().Update(ctx, binding); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, cause
}

// markGroupNotFound is likewise fail-safe (existing RBAC subjects are left
// alone) but, unlike a transient connectivity error, requeues at the normal
// syncInterval cadence: retrying immediately won't make a genuinely absent
// group DN reappear, while periodic re-checks recover automatically if it
// does.
func (r *RBACGroupBindingReconciler) markGroupNotFound(ctx context.Context, binding *ldaprbacv1alpha1.RBACGroupBinding, interval time.Duration) (ctrl.Result, error) {
	recordWarning(r.Recorder, binding, "GroupNotFound", "groupDN not found in directory")
	metrics.SyncTotal.WithLabelValues(rbacGroupBindingKind, "group_not_found").Inc()

	binding.Status.ObservedGeneration = binding.Generation

	meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionReady, Status: metav1.ConditionFalse,
		Reason: ldaprbacv1alpha1.ReasonGroupNotFound, Message: "groupDN not found in directory",
	})
	meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionGroupNotFound, Status: metav1.ConditionTrue,
		Reason: ldaprbacv1alpha1.ReasonGroupNotFound,
	})
	meta.SetStatusCondition(&binding.Status.Conditions, metav1.Condition{
		Type: ldaprbacv1alpha1.ConditionDegraded, Status: metav1.ConditionFalse,
		Reason: ldaprbacv1alpha1.ReasonGroupNotFound,
	})

	if err := r.Status().Update(ctx, binding); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// SetupWithManager wires the reconciler into mgr, including the provider-
// and Secret-change watches described above.
func (r *RBACGroupBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ldaprbacv1alpha1.RBACGroupBinding{}).
		Owns(&rbacv1.RoleBinding{}).
		Watches(&ldaprbacv1alpha1.LDAPProvider{}, handler.EnqueueRequestsFromMapFunc(mapProviderToRBACGroupBindings(mgr.GetClient()))).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapSecretToRBACGroupBindings(mgr.GetClient())),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return obj.GetNamespace() == r.SecretNamespace
			}))).
		Complete(r)
}
