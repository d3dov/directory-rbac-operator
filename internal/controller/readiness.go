package controller

import (
	"context"
	"fmt"
	"net/http"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ldaprbacv1alpha1 "github.com/d3dov/directory-rbac-operator/api/v1alpha1"
)

const readinessCacheTimeout = time.Second

// LDAPProviderReadiness reports readiness from the controller's cached view
// of LDAPProvider status. It deliberately never dials LDAP: a health endpoint
// must remain fast when a remote directory is slow or unavailable. The
// LDAPProvider reconciler performs the actual bind check and persists its
// outcome in the Ready condition.
type LDAPProviderReadiness struct {
	reader  client.Reader
	timeout time.Duration
}

// NewLDAPProviderReadiness creates a readiness checker backed by reader.
func NewLDAPProviderReadiness(reader client.Reader) *LDAPProviderReadiness {
	return &LDAPProviderReadiness{reader: reader, timeout: readinessCacheTimeout}
}

// Check implements controller-runtime's health check contract.
func (r *LDAPProviderReadiness) Check(_ *http.Request) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	var providers ldaprbacv1alpha1.LDAPProviderList
	if err := r.reader.List(ctx, &providers); err != nil {
		return fmt.Errorf("list LDAPProviders from cache: %w", err)
	}

	for i := range providers.Items {
		provider := &providers.Items[i]
		condition := findCondition(provider.Status.Conditions, ldaprbacv1alpha1.ConditionReady)
		if condition == nil {
			return fmt.Errorf("LDAPProvider %q has not completed a readiness check", provider.Name)
		}
		if condition.Status != metav1.ConditionTrue {
			return fmt.Errorf("LDAPProvider %q is not ready: %s", provider.Name, condition.Reason)
		}
	}

	return nil
}

func findCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}
