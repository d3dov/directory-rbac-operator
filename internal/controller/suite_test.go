package controller

import (
	"context"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
	"github.com/denis-da-engineer/directory-rbac-operator/internal/ldapclient"
	"github.com/denis-da-engineer/directory-rbac-operator/internal/ldapclient/fake"
)

var (
	testEnv   *envtest.Environment
	k8sClient client.Client
	ctx       context.Context
	cancel    context.CancelFunc
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.Background())

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	Expect(ldaprbacv1alpha1.AddToScheme(scheme.Scheme)).To(Succeed())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme.Scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	Expect(err).NotTo(HaveOccurred())

	Expect(SetupIndexers(ctx, mgr)).To(Succeed())

	Expect((&RBACGroupBindingReconciler{
		Client:  mgr.GetClient(),
		Scheme:  mgr.GetScheme(),
		Grouper: &stubGrouperResolver{groups: testGroups},
	}).SetupWithManager(mgr)).To(Succeed())

	Expect((&ClusterRBACGroupBindingReconciler{
		Client:  mgr.GetClient(),
		Scheme:  mgr.GetScheme(),
		Grouper: &stubGrouperResolver{groups: testGroups},
	}).SetupWithManager(mgr)).To(Succeed())

	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(ctx)).To(Succeed())
	}()
})

var _ = AfterSuite(func() {
	cancel()
	Expect(testEnv.Stop()).To(Succeed())
})

// testGroups seeds the stub Grouper every spec in this suite resolves
// membership through, since specs exercise the reconciler against a real
// envtest API server but never a real directory.
var testGroups = map[string][]string{
	"cn=data-team,ou=groups,dc=corp,dc=local":       {"alice", "bob"},
	"cn=platform-admins,ou=groups,dc=corp,dc=local": {"carol"},
}

type stubGrouperResolver struct {
	groups map[string][]string
}

func (s *stubGrouperResolver) Grouper(_ context.Context, _ *ldaprbacv1alpha1.LDAPProvider) (ldapclient.Grouper, error) {
	return &fake.Grouper{Groups: s.groups}, nil
}
