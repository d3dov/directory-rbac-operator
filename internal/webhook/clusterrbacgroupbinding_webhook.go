package webhook

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	ldaprbacv1alpha1 "github.com/d3dov/directory-rbac-operator/api/v1alpha1"
)

// ClusterRBACGroupBindingValidator mirrors RBACGroupBindingValidator for the
// cluster-scoped binding type: there is no namespace dimension here, so the
// duplicate check runs against every ClusterRBACGroupBinding cluster-wide.
type ClusterRBACGroupBindingValidator struct {
	Client client.Client
}

var _ admission.Validator[*ldaprbacv1alpha1.ClusterRBACGroupBinding] = (*ClusterRBACGroupBindingValidator)(nil)

// +kubebuilder:webhook:path=/validate-ldaprbac-io-v1alpha1-clusterrbacgroupbinding,mutating=false,failurePolicy=fail,sideEffects=None,groups=ldaprbac.io,resources=clusterrbacgroupbindings,verbs=create;update,versions=v1alpha1,name=vclusterrbacgroupbinding.ldaprbac.io,admissionReviewVersions=v1

// ValidateCreate implements admission.Validator.
func (v *ClusterRBACGroupBindingValidator) ValidateCreate(ctx context.Context, obj *ldaprbacv1alpha1.ClusterRBACGroupBinding) (admission.Warnings, error) {
	return nil, v.rejectDuplicate(ctx, obj)
}

// ValidateUpdate implements admission.Validator.
func (v *ClusterRBACGroupBindingValidator) ValidateUpdate(ctx context.Context, _, newObj *ldaprbacv1alpha1.ClusterRBACGroupBinding) (admission.Warnings, error) {
	return nil, v.rejectDuplicate(ctx, newObj)
}

// ValidateDelete implements admission.Validator.
func (v *ClusterRBACGroupBindingValidator) ValidateDelete(context.Context, *ldaprbacv1alpha1.ClusterRBACGroupBinding) (admission.Warnings, error) {
	return nil, nil
}

func (v *ClusterRBACGroupBindingValidator) rejectDuplicate(ctx context.Context, binding *ldaprbacv1alpha1.ClusterRBACGroupBinding) error {
	var list ldaprbacv1alpha1.ClusterRBACGroupBindingList
	if err := v.Client.List(ctx, &list); err != nil {
		return fmt.Errorf("list existing ClusterRBACGroupBindings: %w", err)
	}

	for _, existing := range list.Items {
		if existing.Name == binding.Name {
			continue // itself, on update
		}
		if existing.Spec.GroupDN == binding.Spec.GroupDN && existing.Spec.ClusterRoleRef == binding.Spec.ClusterRoleRef {
			return fmt.Errorf("groupDN %q is already mapped to clusterRoleRef %q by ClusterRBACGroupBinding %q",
				binding.Spec.GroupDN, existing.Spec.ClusterRoleRef, existing.Name)
		}
	}
	return nil
}

// SetupWebhookWithManager registers the validator with mgr's webhook server.
func (v *ClusterRBACGroupBindingValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &ldaprbacv1alpha1.ClusterRBACGroupBinding{}).
		WithValidator(v).
		Complete()
}
