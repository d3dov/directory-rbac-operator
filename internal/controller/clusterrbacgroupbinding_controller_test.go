package controller

import (
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
)

var _ = Describe("ClusterRBACGroupBindingReconciler", func() {
	const (
		providerName = "corp-ad-cluster"
		groupDN      = "cn=platform-admins,ou=groups,dc=corp,dc=local"
		bindingName  = "platform-admins"
	)

	BeforeEach(func() {
		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: providerName},
			Spec: ldaprbacv1alpha1.LDAPProviderSpec{
				URL:                   "ldaps://ad.corp.local:636",
				BindDN:                "cn=svc,dc=corp,dc=local",
				BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "ldap-bind", Key: "password"},
				UserSearchBase:        "ou=people,dc=corp,dc=local",
				GroupSearchBase:       "ou=groups,dc=corp,dc=local",
				SyncInterval:          metav1.Duration{Duration: time.Minute},
				UsernameAttribute:     "uid",
			},
		}
		Expect(k8sClient.Create(ctx, provider)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, provider))).To(Succeed())
			// See the matching comment in rbacgroupbinding_controller_test.go:
			// the in-use-protection finalizer makes deletion asynchronous.
			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{Name: providerName}, &ldaprbacv1alpha1.LDAPProvider{})
				return apierrors.IsNotFound(err)
			}).Should(BeTrue())
		})
	})

	It("creates a ClusterRoleBinding whose subjects match the resolved group members", func() {
		binding := &ldaprbacv1alpha1.ClusterRBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: bindingName},
			Spec: ldaprbacv1alpha1.ClusterRBACGroupBindingSpec{
				ProviderRef:    providerName,
				GroupDN:        groupDN,
				ClusterRoleRef: "cluster-admin",
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		var crb rbacv1.ClusterRoleBinding
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: bindingName}, &crb)
		}).Should(Succeed())

		Expect(crb.Subjects).To(ConsistOf(
			rbacv1.Subject{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: "carol"},
		))
		Expect(crb.RoleRef).To(Equal(rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"}))

		Eventually(func() (metav1.ConditionStatus, error) {
			var updated ldaprbacv1alpha1.ClusterRBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: bindingName}, &updated); err != nil {
				return "", err
			}
			for _, c := range updated.Status.Conditions {
				if c.Type == ldaprbacv1alpha1.ConditionReady {
					return c.Status, nil
				}
			}
			return "", nil
		}).Should(Equal(metav1.ConditionTrue))
	})

	It("deletes and recreates the ClusterRoleBinding when spec.clusterRoleRef changes, since RoleRef is immutable", func() {
		const immutableBindingName = "platform-admins-roleref-change"

		binding := &ldaprbacv1alpha1.ClusterRBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: immutableBindingName},
			Spec: ldaprbacv1alpha1.ClusterRBACGroupBindingSpec{
				ProviderRef:    providerName,
				GroupDN:        groupDN,
				ClusterRoleRef: "cluster-admin",
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		var crb rbacv1.ClusterRoleBinding
		Eventually(func() (rbacv1.RoleRef, error) {
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: immutableBindingName}, &crb); err != nil {
				return rbacv1.RoleRef{}, err
			}
			return crb.RoleRef, nil
		}).Should(Equal(rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"}))
		originalUID := crb.UID

		Eventually(func() error {
			var updated ldaprbacv1alpha1.ClusterRBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: immutableBindingName}, &updated); err != nil {
				return err
			}
			updated.Spec.ClusterRoleRef = "view"
			return k8sClient.Update(ctx, &updated)
		}).Should(Succeed())

		Eventually(func() (rbacv1.RoleRef, error) {
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: immutableBindingName}, &crb); err != nil {
				return rbacv1.RoleRef{}, err
			}
			return crb.RoleRef, nil
		}).Should(Equal(rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"}))

		Expect(crb.UID).NotTo(Equal(originalUID), "expected a new object (delete+recreate), not an in-place update")
	})

	It("marks GroupNotFound (and not Degraded) when groupDN has no entry in the directory", func() {
		binding := &ldaprbacv1alpha1.ClusterRBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "missing-group-cluster-binding"},
			Spec: ldaprbacv1alpha1.ClusterRBACGroupBindingSpec{
				ProviderRef:    providerName,
				GroupDN:        "cn=does-not-exist,ou=groups,dc=corp,dc=local",
				ClusterRoleRef: "view",
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		Eventually(func() (map[string]metav1.ConditionStatus, error) {
			var updated ldaprbacv1alpha1.ClusterRBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: binding.Name}, &updated); err != nil {
				return nil, err
			}
			out := map[string]metav1.ConditionStatus{}
			for _, c := range updated.Status.Conditions {
				out[c.Type] = c.Status
			}
			return out, nil
		}).Should(SatisfyAll(
			HaveKeyWithValue(ldaprbacv1alpha1.ConditionReady, metav1.ConditionFalse),
			HaveKeyWithValue(ldaprbacv1alpha1.ConditionGroupNotFound, metav1.ConditionTrue),
			HaveKeyWithValue(ldaprbacv1alpha1.ConditionDegraded, metav1.ConditionFalse),
		))

		var crb rbacv1.ClusterRoleBinding
		err := k8sClient.Get(ctx, client.ObjectKey{Name: binding.Name}, &crb)
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "no ClusterRoleBinding should be created for an unresolved group")
	})

	It("marks Degraded when the referenced LDAPProvider does not exist", func() {
		binding := &ldaprbacv1alpha1.ClusterRBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "no-such-provider-cluster-binding"},
			Spec: ldaprbacv1alpha1.ClusterRBACGroupBindingSpec{
				ProviderRef:    "no-such-provider",
				GroupDN:        groupDN,
				ClusterRoleRef: "view",
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		Eventually(func() (metav1.ConditionStatus, error) {
			var updated ldaprbacv1alpha1.ClusterRBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: binding.Name}, &updated); err != nil {
				return "", err
			}
			for _, c := range updated.Status.Conditions {
				if c.Type == ldaprbacv1alpha1.ConditionDegraded {
					return c.Status, nil
				}
			}
			return "", nil
		}).Should(Equal(metav1.ConditionTrue))
	})

	It("marks Degraded when the directory returns an error other than group-not-found", func() {
		const queryErrGroupDN = "cn=query-error-cluster,ou=groups,dc=corp,dc=local"

		clusterRBACGroupBindingGrouper.setForcedGroupError(queryErrGroupDN, errors.New("simulated query failure"))
		DeferCleanup(func() { clusterRBACGroupBindingGrouper.clearForcedGroupError(queryErrGroupDN) })

		binding := &ldaprbacv1alpha1.ClusterRBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "query-error-cluster-binding"},
			Spec: ldaprbacv1alpha1.ClusterRBACGroupBindingSpec{
				ProviderRef:    providerName,
				GroupDN:        queryErrGroupDN,
				ClusterRoleRef: "view",
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		Eventually(func() (map[string]metav1.ConditionStatus, error) {
			var updated ldaprbacv1alpha1.ClusterRBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: binding.Name}, &updated); err != nil {
				return nil, err
			}
			out := map[string]metav1.ConditionStatus{}
			for _, c := range updated.Status.Conditions {
				out[c.Type] = c.Status
			}
			return out, nil
		}).Should(SatisfyAll(
			HaveKeyWithValue(ldaprbacv1alpha1.ConditionDegraded, metav1.ConditionTrue),
			HaveKeyWithValue(ldaprbacv1alpha1.ConditionGroupNotFound, metav1.ConditionFalse),
		))
	})

	It("leaves the managed ClusterRoleBinding's subjects untouched when the directory becomes unreachable", func() {
		const failsafeProvider = "corp-ad-cluster-failsafe"
		const failsafeBinding = "platform-admins-failsafe"

		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: failsafeProvider},
			Spec: ldaprbacv1alpha1.LDAPProviderSpec{
				URL:                   "ldaps://ad.corp.local:636",
				BindDN:                "cn=svc,dc=corp,dc=local",
				BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "ldap-bind", Key: "password"},
				UserSearchBase:        "ou=people,dc=corp,dc=local",
				GroupSearchBase:       "ou=groups,dc=corp,dc=local",
				SyncInterval:          metav1.Duration{Duration: 2 * time.Second},
				UsernameAttribute:     "uid",
			},
		}
		Expect(k8sClient.Create(ctx, provider)).To(Succeed())
		DeferCleanup(func() {
			clusterRBACGroupBindingGrouper.clearForcedError(failsafeProvider)
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, provider))).To(Succeed())
			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{Name: failsafeProvider}, &ldaprbacv1alpha1.LDAPProvider{})
				return apierrors.IsNotFound(err)
			}).Should(BeTrue())
		})

		binding := &ldaprbacv1alpha1.ClusterRBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: failsafeBinding},
			Spec: ldaprbacv1alpha1.ClusterRBACGroupBindingSpec{
				ProviderRef:    failsafeProvider,
				GroupDN:        groupDN,
				ClusterRoleRef: "cluster-admin",
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		var crb rbacv1.ClusterRoleBinding
		subjectsOf := func() ([]rbacv1.Subject, error) {
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: failsafeBinding}, &crb); err != nil {
				return nil, err
			}
			return crb.Subjects, nil
		}
		Eventually(subjectsOf).Should(ConsistOf(rbacv1.Subject{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: "carol"}))

		clusterRBACGroupBindingGrouper.setForcedError(failsafeProvider, errors.New("simulated ldap outage"))

		Eventually(func() (metav1.ConditionStatus, error) {
			var updated ldaprbacv1alpha1.ClusterRBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: failsafeBinding}, &updated); err != nil {
				return "", err
			}
			for _, c := range updated.Status.Conditions {
				if c.Type == ldaprbacv1alpha1.ConditionDegraded {
					return c.Status, nil
				}
			}
			return "", nil
		}, "5s").Should(Equal(metav1.ConditionTrue))

		// The outage keeps triggering reconciles (short syncInterval, plus
		// the default backoff on error); subjects must survive all of them.
		Consistently(subjectsOf, "3s").Should(ConsistOf(rbacv1.Subject{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: "carol"}))
	})
})
