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

// testClusterGroupDN mirrors testGroupDN in rbacgroupbinding_webhook_test.go:
// no test in this file varies it either.
const testClusterGroupDN = "cn=platform-admins,ou=groups,dc=corp,dc=local"

func clusterRBACGroupBinding(name, clusterRoleRef string) *ldaprbacv1alpha1.ClusterRBACGroupBinding {
	return &ldaprbacv1alpha1.ClusterRBACGroupBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       ldaprbacv1alpha1.ClusterRBACGroupBindingSpec{ProviderRef: "corp-ad", GroupDN: testClusterGroupDN, ClusterRoleRef: clusterRoleRef},
	}
}

func TestClusterRBACGroupBindingValidatorAllowsUniqueMapping(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(rbacScheme(t)).Build()
	v := &ClusterRBACGroupBindingValidator{Client: c}

	binding := clusterRBACGroupBinding("platform-admins", "cluster-admin")
	if _, err := v.ValidateCreate(context.Background(), binding); err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil", err)
	}
}

func TestClusterRBACGroupBindingValidatorRejectsDuplicateMapping(t *testing.T) {
	existing := clusterRBACGroupBinding("platform-admins", "cluster-admin")
	c := fake.NewClientBuilder().WithScheme(rbacScheme(t)).WithObjects(existing).Build()
	v := &ClusterRBACGroupBindingValidator{Client: c}

	incoming := clusterRBACGroupBinding("platform-admins-copy", "cluster-admin")
	_, err := v.ValidateCreate(context.Background(), incoming)
	if err == nil {
		t.Fatal("ValidateCreate() error = nil, want a duplicate-mapping error")
	}
	if !strings.Contains(err.Error(), "platform-admins") {
		t.Fatalf("error = %q, want it to name the conflicting binding", err.Error())
	}
}

func TestClusterRBACGroupBindingValidatorAllowsSameGroupDifferentRole(t *testing.T) {
	existing := clusterRBACGroupBinding("platform-admins", "cluster-admin")
	c := fake.NewClientBuilder().WithScheme(rbacScheme(t)).WithObjects(existing).Build()
	v := &ClusterRBACGroupBindingValidator{Client: c}

	incoming := clusterRBACGroupBinding("platform-admins-view", "view")
	if _, err := v.ValidateCreate(context.Background(), incoming); err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil - same group, different role is not a duplicate", err)
	}
}

func TestClusterRBACGroupBindingValidatorIgnoresItselfOnUpdate(t *testing.T) {
	existing := clusterRBACGroupBinding("platform-admins", "cluster-admin")
	c := fake.NewClientBuilder().WithScheme(rbacScheme(t)).WithObjects(existing).Build()
	v := &ClusterRBACGroupBindingValidator{Client: c}

	updated := clusterRBACGroupBinding("platform-admins", "cluster-admin")
	if _, err := v.ValidateUpdate(context.Background(), existing, updated); err != nil {
		t.Fatalf("ValidateUpdate() error = %v, want nil", err)
	}
}

func TestClusterRBACGroupBindingValidatorErrorsOnListFailure(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	v := &ClusterRBACGroupBindingValidator{Client: c}

	binding := clusterRBACGroupBinding("platform-admins", "cluster-admin")
	_, err := v.ValidateCreate(context.Background(), binding)
	if err == nil {
		t.Fatal("ValidateCreate() error = nil, want the List failure to propagate")
	}
}

func TestClusterRBACGroupBindingValidatorValidateDeleteAlwaysAllows(t *testing.T) {
	v := &ClusterRBACGroupBindingValidator{}
	binding := clusterRBACGroupBinding("platform-admins", "cluster-admin")
	if _, err := v.ValidateDelete(context.Background(), binding); err != nil {
		t.Fatalf("ValidateDelete() error = %v, want nil", err)
	}
}
