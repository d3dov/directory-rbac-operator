package rbacsync

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
)

// BuildClusterRoleBinding returns the desired ClusterRoleBinding for binding,
// named to match it - deterministic and needs no separate name tracking.
func BuildClusterRoleBinding(binding *ldaprbacv1alpha1.ClusterRBACGroupBinding, members []string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: binding.Name,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     binding.Spec.ClusterRoleRef,
		},
		Subjects: Subjects(members),
	}
}
