package controller

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
)

// providerRefIndexField lets both binding reconcilers List() their objects
// by the LDAPProvider they reference, which is what the provider-change
// watch mappers use to find dependents without a linear scan.
const providerRefIndexField = ".spec.providerRef"

// secretRefIndexField lets the Secret-rotation watch mappers find every
// LDAPProvider that reads a given Secret (bind password or CA bundle) name,
// without a linear scan. This is a field-index name, not a credential value.
const secretRefIndexField = ".spec.secretRefs" //nolint:gosec // false positive: index name, not a credential

// SetupIndexers registers the field indexers shared by the binding
// reconcilers. Call it once against the manager's cache before starting any
// controller that depends on it.
func SetupIndexers(ctx context.Context, mgr indexerManager) error {
	if err := mgr.GetFieldIndexer().IndexField(ctx, &ldaprbacv1alpha1.RBACGroupBinding{}, providerRefIndexField,
		func(obj client.Object) []string {
			return []string{obj.(*ldaprbacv1alpha1.RBACGroupBinding).Spec.ProviderRef}
		}); err != nil {
		return err
	}

	if err := mgr.GetFieldIndexer().IndexField(ctx, &ldaprbacv1alpha1.ClusterRBACGroupBinding{}, providerRefIndexField,
		func(obj client.Object) []string {
			return []string{obj.(*ldaprbacv1alpha1.ClusterRBACGroupBinding).Spec.ProviderRef}
		}); err != nil {
		return err
	}

	return mgr.GetFieldIndexer().IndexField(ctx, &ldaprbacv1alpha1.LDAPProvider{}, secretRefIndexField,
		func(obj client.Object) []string {
			p := obj.(*ldaprbacv1alpha1.LDAPProvider)
			keys := []string{p.Spec.BindPasswordSecretRef.Name}
			if p.Spec.TLSConfig != nil && p.Spec.TLSConfig.CASecretRef != nil {
				keys = append(keys, p.Spec.TLSConfig.CASecretRef.Name)
			}
			return keys
		})
}

// indexerManager is the subset of ctrl.Manager SetupIndexers needs, so tests
// can pass a bare cache without spinning up a full manager.
type indexerManager interface {
	GetFieldIndexer() client.FieldIndexer
}
