package webhook

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	ldaprbacv1alpha1 "github.com/d3dov/directory-rbac-operator/api/v1alpha1"
)

// RBACGroupBindingValidator rejects a create/update that would leave two
// RBACGroupBindings in the same namespace mapping the same groupDN to the
// same roleRef.
type RBACGroupBindingValidator struct {
	Client client.Client
}

var _ admission.Validator[*ldaprbacv1alpha1.RBACGroupBinding] = (*RBACGroupBindingValidator)(nil)

// +kubebuilder:webhook:path=/validate-ldaprbac-io-v1alpha1-rbacgroupbinding,mutating=false,failurePolicy=fail,sideEffects=None,groups=ldaprbac.io,resources=rbacgroupbindings,verbs=create;update,versions=v1alpha1,name=vrbacgroupbinding.ldaprbac.io,admissionReviewVersions=v1

// ValidateCreate implements admission.Validator.
func (v *RBACGroupBindingValidator) ValidateCreate(ctx context.Context, obj *ldaprbacv1alpha1.RBACGroupBinding) (admission.Warnings, error) {
	return nil, v.rejectDuplicate(ctx, obj)
}

// ValidateUpdate implements admission.Validator. A groupDN or roleRef edit
// can newly collide with a sibling binding just as easily as a create can,
// so this re-runs the same check rather than only checking on create.
func (v *RBACGroupBindingValidator) ValidateUpdate(ctx context.Context, _, newObj *ldaprbacv1alpha1.RBACGroupBinding) (admission.Warnings, error) {
	return nil, v.rejectDuplicate(ctx, newObj)
}

// ValidateDelete implements admission.Validator. Deletion never creates a
// duplicate mapping, so there is nothing to check.
func (v *RBACGroupBindingValidator) ValidateDelete(context.Context, *ldaprbacv1alpha1.RBACGroupBinding) (admission.Warnings, error) {
	return nil, nil
}

func (v *RBACGroupBindingValidator) rejectDuplicate(ctx context.Context, binding *ldaprbacv1alpha1.RBACGroupBinding) error {
	var list ldaprbacv1alpha1.RBACGroupBindingList
	if err := v.Client.List(ctx, &list, client.InNamespace(binding.Namespace)); err != nil {
		return fmt.Errorf("list existing RBACGroupBindings in namespace %q: %w", binding.Namespace, err)
	}

	for _, existing := range list.Items {
		if existing.Name == binding.Name {
			continue // itself, on update
		}
		if existing.Spec.GroupDN == binding.Spec.GroupDN && existing.Spec.RoleRef == binding.Spec.RoleRef {
			return fmt.Errorf("groupDN %q is already mapped to roleRef %s/%s by RBACGroupBinding %q in namespace %q",
				binding.Spec.GroupDN, existing.Spec.RoleRef.Kind, existing.Spec.RoleRef.Name, existing.Name, binding.Namespace)
		}
	}
	return nil
}

// SetupWebhookWithManager registers the validator with mgr's webhook server.
func (v *RBACGroupBindingValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &ldaprbacv1alpha1.RBACGroupBinding{}).
		WithValidator(v).
		Complete()
}
