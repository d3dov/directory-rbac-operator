package controller

import (
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	ldaprbacv1alpha1 "github.com/d3dov/directory-rbac-operator/api/v1alpha1"
)

func TestLDAPProviderReadinessUsesCachedProviderStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		providers []runtime.Object
		wantErr   bool
	}{
		{name: "no providers"},
		{
			name: "provider without a completed bind check",
			providers: []runtime.Object{&ldaprbacv1alpha1.LDAPProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "not-yet-reconciled"},
			}},
			wantErr: true,
		},
		{
			name:      "ready provider",
			providers: []runtime.Object{providerWithReadyCondition(metav1.ConditionTrue, "SyncSucceeded")},
		},
		{
			name:      "degraded provider",
			providers: []runtime.Object{providerWithReadyCondition(metav1.ConditionFalse, "BindFailed")},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scheme := runtime.NewScheme()
			if err := ldaprbacv1alpha1.AddToScheme(scheme); err != nil {
				t.Fatalf("add API scheme: %v", err)
			}
			checker := NewLDAPProviderReadiness(fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(tt.providers...).Build())
			err := checker.Check(httptest.NewRequest("GET", "/readyz", nil))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Check() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func providerWithReadyCondition(status metav1.ConditionStatus, reason string) *ldaprbacv1alpha1.LDAPProvider {
	return &ldaprbacv1alpha1.LDAPProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "corp"},
		Status: ldaprbacv1alpha1.LDAPProviderStatus{Conditions: []metav1.Condition{{
			Type: ldaprbacv1alpha1.ConditionReady, Status: status, Reason: reason,
		}}},
	}
}
