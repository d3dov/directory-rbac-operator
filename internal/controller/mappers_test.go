package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
)

func providerRefIndexFunc(obj client.Object) []string {
	switch o := obj.(type) {
	case *ldaprbacv1alpha1.RBACGroupBinding:
		return []string{o.Spec.ProviderRef}
	case *ldaprbacv1alpha1.ClusterRBACGroupBinding:
		return []string{o.Spec.ProviderRef}
	default:
		return nil
	}
}

func secretRefIndexFunc(obj client.Object) []string {
	p := obj.(*ldaprbacv1alpha1.LDAPProvider) //nolint:forcetypeassert // test-only index func, single caller
	keys := []string{p.Spec.BindPasswordSecretRef.Name}
	if p.Spec.TLSConfig != nil && p.Spec.TLSConfig.CASecretRef != nil {
		keys = append(keys, p.Spec.TLSConfig.CASecretRef.Name)
	}
	return keys
}

func TestMapProviderToRBACGroupBindingsIgnoresNonProviderObjects(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
	requests := mapProviderToRBACGroupBindings(c)(context.Background(), &corev1.Secret{})
	if requests != nil {
		t.Fatalf("mapProviderToRBACGroupBindings() = %v, want nil for a non-LDAPProvider object", requests)
	}
}

func TestMapProviderToClusterRBACGroupBindingsIgnoresNonProviderObjects(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
	requests := mapProviderToClusterRBACGroupBindings(c)(context.Background(), &corev1.Secret{})
	if requests != nil {
		t.Fatalf("mapProviderToClusterRBACGroupBindings() = %v, want nil for a non-LDAPProvider object", requests)
	}
}

func TestMapProviderToRBACGroupBindingsReturnsNilWithoutTheIndex(t *testing.T) {
	// No WithIndex(...) registered: List(client.MatchingFields{...}) fails,
	// exercising the mapper's "give up on List error" branch.
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
	provider := &ldaprbacv1alpha1.LDAPProvider{ObjectMeta: metav1.ObjectMeta{Name: "corp"}}

	requests := mapProviderToRBACGroupBindings(c)(context.Background(), provider)
	if requests != nil {
		t.Fatalf("mapProviderToRBACGroupBindings() = %v, want nil when the index lookup fails", requests)
	}
}

func TestMapProviderToClusterRBACGroupBindingsReturnsNilWithoutTheIndex(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
	provider := &ldaprbacv1alpha1.LDAPProvider{ObjectMeta: metav1.ObjectMeta{Name: "corp"}}

	requests := mapProviderToClusterRBACGroupBindings(c)(context.Background(), provider)
	if requests != nil {
		t.Fatalf("mapProviderToClusterRBACGroupBindings() = %v, want nil when the index lookup fails", requests)
	}
}

func TestProvidersReferencingSecretReturnsNilWithoutTheIndex(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()

	providers := providersReferencingSecret(context.Background(), c, "bind-credentials")
	if providers != nil {
		t.Fatalf("providersReferencingSecret() = %v, want nil when the index lookup fails", providers)
	}
}

func TestMapSecretToRBACGroupBindingsSkipsProviderWhenInnerListFails(t *testing.T) {
	// secretRefIndexField is registered (so providersReferencingSecret finds
	// "corp"), but providerRefIndexField isn't, so the inner List for
	// RBACGroupBindingList fails and that provider is skipped rather than
	// panicking or aborting the whole mapper.
	scheme := newTestScheme(t)
	provider := &ldaprbacv1alpha1.LDAPProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "corp"},
		Spec:       ldaprbacv1alpha1.LDAPProviderSpec{BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "bind-credentials"}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&ldaprbacv1alpha1.LDAPProvider{}, secretRefIndexField, secretRefIndexFunc).
		WithObjects(provider).
		Build()

	requests := mapSecretToRBACGroupBindings(c)(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bind-credentials"}})
	if len(requests) != 0 {
		t.Fatalf("mapSecretToRBACGroupBindings() = %v, want none when the inner List fails", requests)
	}
}

func TestMapSecretToClusterRBACGroupBindingsSkipsProviderWhenInnerListFails(t *testing.T) {
	scheme := newTestScheme(t)
	provider := &ldaprbacv1alpha1.LDAPProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "corp"},
		Spec:       ldaprbacv1alpha1.LDAPProviderSpec{BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "bind-credentials"}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&ldaprbacv1alpha1.LDAPProvider{}, secretRefIndexField, secretRefIndexFunc).
		WithObjects(provider).
		Build()

	requests := mapSecretToClusterRBACGroupBindings(c)(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bind-credentials"}})
	if len(requests) != 0 {
		t.Fatalf("mapSecretToClusterRBACGroupBindings() = %v, want none when the inner List fails", requests)
	}
}

func TestMapSecretToClusterRBACGroupBindingsReturnsMatchingBindings(t *testing.T) {
	scheme := newTestScheme(t)
	provider := &ldaprbacv1alpha1.LDAPProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "corp"},
		Spec:       ldaprbacv1alpha1.LDAPProviderSpec{BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "bind-credentials"}},
	}
	binding := &ldaprbacv1alpha1.ClusterRBACGroupBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "platform-admins"},
		Spec:       ldaprbacv1alpha1.ClusterRBACGroupBindingSpec{ProviderRef: "corp"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&ldaprbacv1alpha1.LDAPProvider{}, secretRefIndexField, secretRefIndexFunc).
		WithIndex(&ldaprbacv1alpha1.ClusterRBACGroupBinding{}, providerRefIndexField, providerRefIndexFunc).
		WithObjects(provider, binding).
		Build()

	requests := mapSecretToClusterRBACGroupBindings(c)(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bind-credentials"}})
	if len(requests) != 1 || requests[0].Name != "platform-admins" {
		t.Fatalf("mapSecretToClusterRBACGroupBindings() = %v, want a single request for platform-admins", requests)
	}
}
