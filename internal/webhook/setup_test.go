package webhook

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	ldaprbacv1alpha1 "github.com/d3dov/directory-rbac-operator/api/v1alpha1"
)

// newTestManager builds a manager against a REST config that's never
// actually dialed: SetupWebhookWithManager only needs mgr.GetScheme() (to
// resolve the GVK) and mgr.GetWebhookServer() (to register an in-process
// HTTP handler), neither of which touches the network, so this covers the
// registration wiring itself without the cost of a full envtest apiserver.
func newTestManager(t *testing.T) ctrl.Manager {
	t.Helper()

	scheme := runtime.NewScheme()
	utilruntime.Must(ldaprbacv1alpha1.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(&rest.Config{Host: "http://127.0.0.1:1"}, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return mgr
}

func TestRBACGroupBindingValidatorSetupWebhookWithManager(t *testing.T) {
	mgr := newTestManager(t)
	v := &RBACGroupBindingValidator{Client: mgr.GetClient()}
	if err := v.SetupWebhookWithManager(mgr); err != nil {
		t.Fatalf("SetupWebhookWithManager() error = %v, want nil", err)
	}
}

func TestClusterRBACGroupBindingValidatorSetupWebhookWithManager(t *testing.T) {
	mgr := newTestManager(t)
	v := &ClusterRBACGroupBindingValidator{Client: mgr.GetClient()}
	if err := v.SetupWebhookWithManager(mgr); err != nil {
		t.Fatalf("SetupWebhookWithManager() error = %v, want nil", err)
	}
}
