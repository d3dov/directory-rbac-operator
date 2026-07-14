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

const clusterRBACGroupBindingKind = "ClusterRBACGroupBinding"

// ClusterRBACGroupBindingReconciler syncs a ClusterRoleBinding's subjects to
// an LDAP/AD group's membership. It mirrors RBACGroupBindingReconciler for
// the cluster-scoped binding type.
type ClusterRBACGroupBindingReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Grouper  GrouperResolver
	Recorder events.EventRecorder

	// SecretNamespace scopes the Secret-rotation watch below; see the
	// matching field on RBACGroupBindingReconciler.
	SecretNamespace string
}

// +kubebuilder:rbac:groups=ldaprbac.io,resources=clusterrbacgroupbindings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=ldaprbac.io,resources=clusterrbacgroupbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete

// Reconcile mirrors RBACGroupBindingReconciler.Reconcile closely enough that
// dupl flags it; unifying the two via generics/interfaces would trade a
// small amount of duplication for a layer of indirection between two
// concrete, differently-scoped Kubernetes object types (RoleBinding vs
// ClusterRoleBinding, namespaced vs cluster CRs) - not a clear improvement,
// and kubebuilder itself scaffolds separate reconcilers for exactly this
// kind of pair.
//
//nolint:dupl // see comment above
func (r *ClusterRBACGroupBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	defer func() {
		metrics.SyncDuration.WithLabelValues(clusterRBACGroupBindingKind).Observe(time.Since(start).Seconds())
	}()

	log := logf.FromContext(ctx)

	var binding ldaprbacv1alpha1.ClusterRBACGroupBinding
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

	desired := rbacsync.BuildClusterRoleBinding(&binding, members)
	if err := controllerutil.SetControllerReference(&binding, desired, r.Scheme); err != nil {
		return ctrl.Result{}, err
	}

	outcome, err := r.reconcileClusterRoleBinding(ctx, desired)
	if err != nil {
		return r.markDegraded(ctx, &binding, err)
	}

	switch outcome {
	case syncUnchanged:
		// nothing changed; no event to record.
	case syncCreated:
		recordSuccessf(r.Recorder, &binding, "ClusterRoleBindingCreated", "created ClusterRoleBinding %s with %d member(s)", desired.Name, len(members))
	case syncUpdated:
		recordSuccessf(r.Recorder, &binding, "ClusterRoleBindingUpdated", "updated ClusterRoleBinding %s to %d member(s)", desired.Name, len(members))
	case syncRecreated:
		recordSuccessf(r.Recorder, &binding, "ClusterRoleBindingRecreated", "recreated ClusterRoleBinding %s (clusterRoleRef changed)", desired.Name)
	}

	log.Info("synced group membership", "members", len(members))
	return r.markReady(ctx, &binding, members, provider.Spec.SyncInterval.Duration)
}

func (r *ClusterRBACGroupBindingReconciler) reconcileClusterRoleBinding(ctx context.Context, desired *rbacv1.ClusterRoleBinding) (syncOutcome, error) {
	var existing rbacv1.ClusterRoleBinding
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
		// RoleRef is immutable on an existing ClusterRoleBinding, so a
		// spec.clusterRoleRef edit is applied by deleting and recreating
		// rather than updating.
		if err := r.Delete(ctx, &existing); err != nil {
			return syncUnchanged, err
		}
		if err := r.Create(ctx, desired); err != nil {
			return syncUnchanged, err
		}
		return syncRecreated, nil
	}

	// OwnerReferences is checked alongside Subjects for the same reason as
	// RBACGroupBindingReconciler.reconcileRoleBinding: without a garbage
	// collector guaranteeing a same-named prior object is gone first,
	// "existing" could be a leftover ClusterRoleBinding from a different,
	// already-deleted binding of the same name.
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

func (r *ClusterRBACGroupBindingReconciler) markReady(ctx context.Context, binding *ldaprbacv1alpha1.ClusterRBACGroupBinding, members []string, interval time.Duration) (ctrl.Result, error) {
	preview, truncated := rbacsync.PreviewMembers(members)

	binding.Status.ObservedGeneration = binding.Generation
	now := metav1.Now()
	binding.Status.LastSyncTime = &now
	binding.Status.MemberCount = rbacsync.MemberCount(members)
	binding.Status.MembersPreview = preview
	binding.Status.MembersTruncated = truncated
	binding.Status.MembersHash = rbacsync.MembersHash(members)
	binding.Status.ClusterRoleBindingRef = &corev1.LocalObjectReference{Name: binding.Name}

	metrics.SyncTotal.WithLabelValues(clusterRBACGroupBindingKind, "ready").Inc()
	metrics.MembersCount.WithLabelValues(clusterRBACGroupBindingKind, "", binding.Name).Set(float64(len(members)))

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

// markDegraded and markGroupNotFound below mirror
// RBACGroupBindingReconciler's; see the Reconcile comment above for why
// that's left as-is rather than unified. markDegraded's ctrl.Result is
// always the zero value, deliberately mirroring Reconcile's return shape so
// callers can `return r.markDegraded(...)` directly.
//
//nolint:dupl,unparam // see comment above
func (r *ClusterRBACGroupBindingReconciler) markDegraded(ctx context.Context, binding *ldaprbacv1alpha1.ClusterRBACGroupBinding, cause error) (ctrl.Result, error) {
	recordWarning(r.Recorder, binding, "SyncFailed", cause.Error())
	metrics.SyncTotal.WithLabelValues(clusterRBACGroupBindingKind, "degraded").Inc()
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

func (r *ClusterRBACGroupBindingReconciler) markGroupNotFound(ctx context.Context, binding *ldaprbacv1alpha1.ClusterRBACGroupBinding, interval time.Duration) (ctrl.Result, error) {
	recordWarning(r.Recorder, binding, "GroupNotFound", "groupDN not found in directory")
	metrics.SyncTotal.WithLabelValues(clusterRBACGroupBindingKind, "group_not_found").Inc()

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
func (r *ClusterRBACGroupBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ldaprbacv1alpha1.ClusterRBACGroupBinding{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Watches(&ldaprbacv1alpha1.LDAPProvider{}, handler.EnqueueRequestsFromMapFunc(mapProviderToClusterRBACGroupBindings(mgr.GetClient()))).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapSecretToClusterRBACGroupBindings(mgr.GetClient())),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return obj.GetNamespace() == r.SecretNamespace
			}))).
		Complete(r)
}
