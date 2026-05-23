// Package rbacsync builds and diffs the RBAC objects (RoleBinding,
// ClusterRoleBinding) managed from resolved LDAP/AD group membership.
package rbacsync

import (
	rbacv1 "k8s.io/api/rbac/v1"
)

// Subjects converts resolved member names into RBAC User subjects. Members
// are expected to already be projected through the provider's configured
// username attribute (LDAPProviderSpec.UsernameAttribute), so the value is
// used verbatim - it must byte-match whatever the cluster's OIDC/Dex layer
// presents as the authenticated username claim.
func Subjects(members []string) []rbacv1.Subject {
	subjects := make([]rbacv1.Subject, 0, len(members))
	for _, m := range members {
		subjects = append(subjects, rbacv1.Subject{
			Kind:     rbacv1.UserKind,
			APIGroup: rbacv1.GroupName,
			Name:     m,
		})
	}
	return subjects
}
