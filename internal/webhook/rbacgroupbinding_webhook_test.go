package webhook

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	ldaprbacv1alpha1 "github.com/d3dov/directory-rbac-operator/api/v1alpha1"
)

func rbacScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := ldaprbacv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}
	return scheme
}

// testGroupDN is shared by every test in this file: none of them vary it,
// since the duplicate check keys on (groupDN, roleRef) together and the
// roleRef argument alone is enough to distinguish test cases.
const testGroupDN = "cn=data-team,ou=groups,dc=corp,dc=local"

func rbacGroupBinding(name, namespace string, roleRef ldaprbacv1alpha1.RoleRef) *ldaprbacv1alpha1.RBACGroupBinding {
	return &ldaprbacv1alpha1.RBACGroupBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       ldaprbacv1alpha1.RBACGroupBindingSpec{ProviderRef: "corp-ad", GroupDN: testGroupDN, RoleRef: roleRef},
	}
}

func TestRBACGroupBindingValidatorAllowsUniqueMapping(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(rbacScheme(t)).Build()
	v := &RBACGroupBindingValidator{Client: c}

	binding := rbacGroupBinding("data-team-edit", "default", ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"})
	if _, err := v.ValidateCreate(context.Background(), binding); err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil", err)
	}
}

func TestRBACGroupBindingValidatorRejectsDuplicateMapping(t *testing.T) {
	roleRef := ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"}
	existing := rbacGroupBinding("data-team-edit", "default", roleRef)
	c := fake.NewClientBuilder().WithScheme(rbacScheme(t)).WithObjects(existing).Build()
	v := &RBACGroupBindingValidator{Client: c}

	incoming := rbacGroupBinding("data-team-edit-copy", "default", roleRef)
	_, err := v.ValidateCreate(context.Background(), incoming)
	if err == nil {
		t.Fatal("ValidateCreate() error = nil, want a duplicate-mapping error")
	}
	if !strings.Contains(err.Error(), "data-team-edit") {
		t.Fatalf("error = %q, want it to name the conflicting binding", err.Error())
	}
}

func TestRBACGroupBindingValidatorAllowsSameGroupDifferentRole(t *testing.T) {
	existing := rbacGroupBinding("data-team-edit", "default", ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"})
	c := fake.NewClientBuilder().WithScheme(rbacScheme(t)).WithObjects(existing).Build()
	v := &RBACGroupBindingValidator{Client: c}

	incoming := rbacGroupBinding("data-team-view", "default", ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "view"})
	if _, err := v.ValidateCreate(context.Background(), incoming); err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil - same group, different role is not a duplicate", err)
	}
}

func TestRBACGroupBindingValidatorAllowsSameMappingDifferentNamespace(t *testing.T) {
	roleRef := ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"}
	existing := rbacGroupBinding("data-team-edit", "team-a", roleRef)
	c := fake.NewClientBuilder().WithScheme(rbacScheme(t)).WithObjects(existing).Build()
	v := &RBACGroupBindingValidator{Client: c}

	incoming := rbacGroupBinding("data-team-edit", "team-b", roleRef)
	if _, err := v.ValidateCreate(context.Background(), incoming); err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil - namespaces isolate the duplicate check", err)
	}
}

func TestRBACGroupBindingValidatorIgnoresItselfOnUpdate(t *testing.T) {
	roleRef := ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"}
	existing := rbacGroupBinding("data-team-edit", "default", roleRef)
	c := fake.NewClientBuilder().WithScheme(rbacScheme(t)).WithObjects(existing).Build()
	v := &RBACGroupBindingValidator{Client: c}

	// Same name as the only existing binding: an update must not collide
	// with itself.
	updated := rbacGroupBinding("data-team-edit", "default", roleRef)
	if _, err := v.ValidateUpdate(context.Background(), existing, updated); err != nil {
		t.Fatalf("ValidateUpdate() error = %v, want nil", err)
	}
}

func TestRBACGroupBindingValidatorErrorsOnListFailure(t *testing.T) {
	// An empty scheme makes List fail (the fake client can't decode
	// RBACGroupBindingList without it registered).
	c := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	v := &RBACGroupBindingValidator{Client: c}

	binding := rbacGroupBinding("data-team-edit", "default", ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"})
	_, err := v.ValidateCreate(context.Background(), binding)
	if err == nil {
		t.Fatal("ValidateCreate() error = nil, want the List failure to propagate")
	}
}

func TestRBACGroupBindingValidatorValidateDeleteAlwaysAllows(t *testing.T) {
	v := &RBACGroupBindingValidator{}
	binding := rbacGroupBinding("data-team-edit", "default", ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"})
	if _, err := v.ValidateDelete(context.Background(), binding); err != nil {
		t.Fatalf("ValidateDelete() error = %v, want nil", err)
	}
}
