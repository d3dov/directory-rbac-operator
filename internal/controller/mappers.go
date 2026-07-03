package controller

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
)

// mapProviderToRBACGroupBindings enqueues every RBACGroupBinding that
// references a changed LDAPProvider, so e.g. a syncInterval or URL edit on
// the provider is picked up without waiting for each binding's own timer.
func mapProviderToRBACGroupBindings(c client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		provider, ok := obj.(*ldaprbacv1alpha1.LDAPProvider)
		if !ok {
			return nil
		}

		var list ldaprbacv1alpha1.RBACGroupBindingList
		if err := c.List(ctx, &list, client.MatchingFields{providerRefIndexField: provider.Name}); err != nil {
			return nil
		}

		requests := make([]reconcile.Request, 0, len(list.Items))
		for _, item := range list.Items {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&item)})
		}
		return requests
	}
}

// mapProviderToClusterRBACGroupBindings mirrors mapProviderToRBACGroupBindings
// for the cluster-scoped binding type.
func mapProviderToClusterRBACGroupBindings(c client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		provider, ok := obj.(*ldaprbacv1alpha1.LDAPProvider)
		if !ok {
			return nil
		}

		var list ldaprbacv1alpha1.ClusterRBACGroupBindingList
		if err := c.List(ctx, &list, client.MatchingFields{providerRefIndexField: provider.Name}); err != nil {
			return nil
		}

		requests := make([]reconcile.Request, 0, len(list.Items))
		for _, item := range list.Items {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&item)})
		}
		return requests
	}
}

// providersReferencingSecret finds every LDAPProvider that reads secretName
// (as its bind password or CA bundle), the first hop of the two-hop
// Secret -> LDAPProvider -> binding cascade below.
func providersReferencingSecret(ctx context.Context, c client.Client, secretName string) []ldaprbacv1alpha1.LDAPProvider {
	var providers ldaprbacv1alpha1.LDAPProviderList
	if err := c.List(ctx, &providers, client.MatchingFields{secretRefIndexField: secretName}); err != nil {
		return nil
	}
	return providers.Items
}

// mapSecretToRBACGroupBindings enqueues every RBACGroupBinding whose
// LDAPProvider reads the changed Secret, so rotating a bind password or CA
// bundle is picked up without waiting for the next syncInterval.
func mapSecretToRBACGroupBindings(c client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		var requests []reconcile.Request
		for _, provider := range providersReferencingSecret(ctx, c, obj.GetName()) {
			var list ldaprbacv1alpha1.RBACGroupBindingList
			if err := c.List(ctx, &list, client.MatchingFields{providerRefIndexField: provider.Name}); err != nil {
				continue
			}
			for _, item := range list.Items {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&item)})
			}
		}
		return requests
	}
}

// mapSecretToClusterRBACGroupBindings mirrors mapSecretToRBACGroupBindings
// for the cluster-scoped binding type.
func mapSecretToClusterRBACGroupBindings(c client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		var requests []reconcile.Request
		for _, provider := range providersReferencingSecret(ctx, c, obj.GetName()) {
			var list ldaprbacv1alpha1.ClusterRBACGroupBindingList
			if err := c.List(ctx, &list, client.MatchingFields{providerRefIndexField: provider.Name}); err != nil {
				continue
			}
			for _, item := range list.Items {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&item)})
			}
		}
		return requests
	}
}
