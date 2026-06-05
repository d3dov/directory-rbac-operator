package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
	"github.com/denis-da-engineer/directory-rbac-operator/internal/ldapclient"
	"github.com/denis-da-engineer/directory-rbac-operator/internal/rbacsync"
)

// ClusterRBACGroupBindingReconciler syncs a ClusterRoleBinding's subjects to
// an LDAP/AD group's membership. It mirrors RBACGroupBindingReconciler for
// the cluster-scoped binding type.
type ClusterRBACGroupBindingReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	Grouper GrouperResolver
}

// +kubebuilder:rbac:groups=ldaprbac.io,resources=clusterrbacgroupbindings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=ldaprbac.io,resources=clusterrbacgroupbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete

func (r *ClusterRBACGroupBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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

	if err := r.reconcileClusterRoleBinding(ctx, desired); err != nil {
		return r.markDegraded(ctx, &binding, err)
	}

	log.Info("synced group membership", "members", len(members))
	return r.markReady(ctx, &binding, members, provider.Spec.SyncInterval.Duration)
}

func (r *ClusterRBACGroupBindingReconciler) reconcileClusterRoleBinding(ctx context.Context, desired *rbacv1.ClusterRoleBinding) error {
	var existing rbacv1.ClusterRoleBinding
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	switch {
	case apierrors.IsNotFound(err):
		return r.Create(ctx, desired)
	case err != nil:
		return err
	}

	if existing.RoleRef != desired.RoleRef {
		// RoleRef is immutable on an existing ClusterRoleBinding, so a
		// spec.clusterRoleRef edit is applied by deleting and recreating
		// rather than updating.
		if err := r.Delete(ctx, &existing); err != nil {
			return err
		}
		return r.Create(ctx, desired)
	}

	if rbacsync.SubjectsEqual(existing.Subjects, desired.Subjects) {
		return nil
	}

	existing.Subjects = desired.Subjects
	return r.Update(ctx, &existing)
}

func (r *ClusterRBACGroupBindingReconciler) markReady(ctx context.Context, binding *ldaprbacv1alpha1.ClusterRBACGroupBinding, members []string, interval time.Duration) (ctrl.Result, error) {
	preview, truncated := rbacsync.PreviewMembers(members)

	binding.Status.ObservedGeneration = binding.Generation
	now := metav1.Now()
	binding.Status.LastSyncTime = &now
	binding.Status.MemberCount = int32(len(members))
	binding.Status.MembersPreview = preview
	binding.Status.MembersTruncated = truncated
	binding.Status.MembersHash = rbacsync.MembersHash(members)
	binding.Status.ClusterRoleBindingRef = &corev1.LocalObjectReference{Name: binding.Name}

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

func (r *ClusterRBACGroupBindingReconciler) markDegraded(ctx context.Context, binding *ldaprbacv1alpha1.ClusterRBACGroupBinding, cause error) (ctrl.Result, error) {
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

func (r *ClusterRBACGroupBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ldaprbacv1alpha1.ClusterRBACGroupBinding{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Watches(&ldaprbacv1alpha1.LDAPProvider{}, handler.EnqueueRequestsFromMapFunc(mapProviderToClusterRBACGroupBindings(mgr.GetClient()))).
		Complete(r)
}
