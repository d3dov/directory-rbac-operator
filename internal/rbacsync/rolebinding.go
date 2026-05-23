package rbacsync

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
)

// BuildRoleBinding returns the desired RoleBinding for binding, named and
// namespaced to match it - deterministic and needs no separate name
// tracking.
func BuildRoleBinding(binding *ldaprbacv1alpha1.RBACGroupBinding, members []string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      binding.Name,
			Namespace: binding.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     binding.Spec.RoleRef.Kind,
			Name:     binding.Spec.RoleRef.Name,
		},
		Subjects: Subjects(members),
	}
}
