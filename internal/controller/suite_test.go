package controller

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

	inUseRecheckInterval = 200 * time.Millisecond

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
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Grouper:         rbacGroupBindingGrouper,
		Recorder:        mgr.GetEventRecorder("rbacgroupbinding-controller"),
		SecretNamespace: testSecretNamespace,
	}).SetupWithManager(mgr)).To(Succeed())

	Expect((&ClusterRBACGroupBindingReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Grouper:         clusterRBACGroupBindingGrouper,
		Recorder:        mgr.GetEventRecorder("clusterrbacgroupbinding-controller"),
		SecretNamespace: testSecretNamespace,
	}).SetupWithManager(mgr)).To(Succeed())

	Expect((&LDAPProviderReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Pinger:   ldapProviderPinger,
		Recorder: mgr.GetEventRecorder("ldapprovider-controller"),
		Limiters: ldapProviderLimiters,
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

// testSecretNamespace matches --secret-namespace in production wiring;
// "default" is where every test in this suite already creates its objects.
const testSecretNamespace = "default"

// testGroups seeds the stub Grouper every spec in this suite resolves
// membership through, since specs exercise the reconciler against a real
// envtest API server but never a real directory.
var testGroups = map[string][]string{
	"cn=data-team,ou=groups,dc=corp,dc=local":       {"alice", "bob"},
	"cn=platform-admins,ou=groups,dc=corp,dc=local": {"carol"},
}

// rbacGroupBindingGrouper and clusterRBACGroupBindingGrouper are the
// GrouperResolvers wired into the two binding reconcilers under test, kept
// as suite-level vars so fail-safe specs can inject a forced error for a
// specific provider (simulating an LDAP outage) without a real directory.
var (
	rbacGroupBindingGrouper        = &stubGrouperResolver{groups: testGroups}
	clusterRBACGroupBindingGrouper = &stubGrouperResolver{groups: testGroups}
)

type stubGrouperResolver struct {
	groups map[string][]string

	mu             sync.Mutex
	forcedErr      map[string]error
	forcedGroupErr map[string]error
}

func (s *stubGrouperResolver) Grouper(_ context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (ldapclient.Grouper, error) {
	s.mu.Lock()
	err := s.forcedErr[provider.Name]
	groupErrs := s.forcedGroupErr
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &fake.Grouper{Groups: s.groups, Errors: groupErrs}, nil
}

// setForcedError makes every subsequent Grouper() call for providerName fail
// with err, as if the directory had become unreachable.
func (s *stubGrouperResolver) setForcedError(providerName string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forcedErr == nil {
		s.forcedErr = map[string]error{}
	}
	s.forcedErr[providerName] = err
}

func (s *stubGrouperResolver) clearForcedError(providerName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.forcedErr, providerName)
}

// setForcedGroupError makes GetGroupMembers(groupDN) fail with err, unlike
// setForcedError above (which fails resolving a Grouper at all) - this
// simulates a directory error distinct from a confirmed-absent group, which
// a Groups miss already covers.
func (s *stubGrouperResolver) setForcedGroupError(groupDN string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forcedGroupErr == nil {
		s.forcedGroupErr = map[string]error{}
	}
	s.forcedGroupErr[groupDN] = err
}

func (s *stubGrouperResolver) clearForcedGroupError(groupDN string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.forcedGroupErr, groupDN)
}

// ldapProviderPinger is the PingerResolver LDAPProviderReconciler is wired
// against, kept as a suite-level var so a specific spec can force a bind
// failure (simulating an unreachable directory) without a real one.
var ldapProviderPinger = &stubPingerResolver{}

// ldapProviderLimiters is the same registry a real GrouperFactory would draw
// rate limiters from; kept as a suite-level var so a spec can prove
// LDAPProviderReconciler cleans up a deleted provider's entry.
var ldapProviderLimiters = &ldapclient.Limiters{}

// stubPingerResolver reports success by default, since most health-check
// specs only exercise LDAPProviderReconciler's own TLS-validation and status
// wiring, never a real bind.
type stubPingerResolver struct {
	mu        sync.Mutex
	forcedErr map[string]error
}

func (s *stubPingerResolver) Pinger(_ context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (ldapclient.Pinger, error) {
	s.mu.Lock()
	err := s.forcedErr[provider.Name]
	s.mu.Unlock()
	return stubPinger{err: err}, nil
}

// setForcedError makes every subsequent Ping() for providerName fail with
// err, as if the directory had become unreachable.
func (s *stubPingerResolver) setForcedError(providerName string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forcedErr == nil {
		s.forcedErr = map[string]error{}
	}
	s.forcedErr[providerName] = err
}

func (s *stubPingerResolver) clearForcedError(providerName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.forcedErr, providerName)
}

type stubPinger struct{ err error }

func (p stubPinger) Ping(_ context.Context) error { return p.err }
