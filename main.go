// Command directory-rbac-operator runs the controller manager: the
// RBACGroupBinding, ClusterRBACGroupBinding and LDAPProvider reconcilers.
package main

import (
	"context"
	"flag"
	"os"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	ldaprbacv1alpha1 "github.com/d3dov/directory-rbac-operator/api/v1alpha1"
	"github.com/d3dov/directory-rbac-operator/internal/controller"
	"github.com/d3dov/directory-rbac-operator/internal/ldapclient"
	"github.com/d3dov/directory-rbac-operator/internal/version"
	"github.com/d3dov/directory-rbac-operator/internal/webhook"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ldaprbacv1alpha1.AddToScheme(scheme))
}

// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func main() {
	var metricsAddr string
	var probeAddr string
	var enableLeaderElection bool
	var secretNamespace string
	var enableValidatingWebhook bool

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address the metrics endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address the health probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for the manager. Ensures only one active instance when running with multiple replicas.")
	flag.StringVar(&secretNamespace, "secret-namespace", "directory-rbac-operator-system",
		"Namespace consulted for every LDAPProvider's bindPasswordSecretRef/tlsConfig.caSecretRef. "+
			"LDAPProvider is cluster-scoped and so cannot carry a Secret namespace of its own.")
	flag.BoolVar(&enableValidatingWebhook, "enable-validating-webhook", false,
		"Serve the validating webhook that rejects a RBACGroupBinding/ClusterRBACGroupBinding duplicating "+
			"another one's group-to-role mapping. Requires a TLS cert/key at the webhook server's cert dir "+
			"(see the Helm chart's webhook.enabled value, which wires this up via cert-manager) and a matching "+
			"ValidatingWebhookConfiguration; off by default so a plain install doesn't need either.")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("starting directory-rbac-operator", "version", version.Version)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "directory-rbac-operator.ldaprbac.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := controller.SetupIndexers(context.Background(), mgr); err != nil {
		setupLog.Error(err, "unable to set up field indexers")
		os.Exit(1)
	}

	limiters := &ldapclient.Limiters{}
	grouperFactory := &controller.GrouperFactory{Client: mgr.GetClient(), SecretNamespace: secretNamespace, Limiters: limiters}

	if err := (&controller.RBACGroupBindingReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Grouper:         grouperFactory,
		Recorder:        mgr.GetEventRecorder("rbacgroupbinding-controller"),
		SecretNamespace: secretNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "RBACGroupBinding")
		os.Exit(1)
	}

	if err := (&controller.ClusterRBACGroupBindingReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Grouper:         grouperFactory,
		Recorder:        mgr.GetEventRecorder("clusterrbacgroupbinding-controller"),
		SecretNamespace: secretNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterRBACGroupBinding")
		os.Exit(1)
	}

	if err := (&controller.LDAPProviderReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Pinger:   grouperFactory,
		Recorder: mgr.GetEventRecorder("ldapprovider-controller"),
		Limiters: limiters,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "LDAPProvider")
		os.Exit(1)
	}

	if enableValidatingWebhook {
		setupWebhooks(mgr, setupLog)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", controller.NewLDAPProviderReadiness(mgr.GetClient()).Check); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// setupWebhooks registers the validating webhooks that reject a duplicate
// group-to-role mapping. Exits the process on failure, matching every other
// setup step in main.
func setupWebhooks(mgr ctrl.Manager, setupLog logr.Logger) {
	if err := (&webhook.RBACGroupBindingValidator{Client: mgr.GetClient()}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "RBACGroupBinding")
		os.Exit(1)
	}
	if err := (&webhook.ClusterRBACGroupBindingValidator{Client: mgr.GetClient()}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "ClusterRBACGroupBinding")
		os.Exit(1)
	}
}
