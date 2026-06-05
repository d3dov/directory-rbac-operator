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

var _ = Describe("RBACGroupBindingReconciler", func() {
	const (
		providerName = "corp-ad"
		groupDN      = "cn=data-team,ou=groups,dc=corp,dc=local"
		namespace    = "default"
		bindingName  = "data-team-edit"
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
			// LDAPProvider carries an in-use-protection finalizer, so
			// deletion only completes once the reconciler observes no
			// dependent bindings - wait for that, or the next spec's
			// same-name Create races the still-terminating object.
			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{Name: providerName}, &ldaprbacv1alpha1.LDAPProvider{})
				return apierrors.IsNotFound(err)
			}).Should(BeTrue())
		})
	})

	It("creates a RoleBinding whose subjects match the resolved group members", func() {
		binding := &ldaprbacv1alpha1.RBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: bindingName, Namespace: namespace},
			Spec: ldaprbacv1alpha1.RBACGroupBindingSpec{
				ProviderRef: providerName,
				GroupDN:     groupDN,
				RoleRef:     ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"},
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		var rb rbacv1.RoleBinding
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: bindingName, Namespace: namespace}, &rb)
		}).Should(Succeed())

		Expect(rb.Subjects).To(ConsistOf(
			rbacv1.Subject{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: "alice"},
			rbacv1.Subject{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: "bob"},
		))
		Expect(rb.RoleRef).To(Equal(rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "edit"}))

		Eventually(func() (metav1.ConditionStatus, error) {
			var updated ldaprbacv1alpha1.RBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: bindingName, Namespace: namespace}, &updated); err != nil {
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

	It("marks GroupNotFound (and not Degraded) when groupDN has no entry in the directory", func() {
		binding := &ldaprbacv1alpha1.RBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "missing-group-binding", Namespace: namespace},
			Spec: ldaprbacv1alpha1.RBACGroupBindingSpec{
				ProviderRef: providerName,
				GroupDN:     "cn=does-not-exist,ou=groups,dc=corp,dc=local",
				RoleRef:     ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "view"},
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		conditionsByType := func() (map[string]metav1.ConditionStatus, error) {
			var updated ldaprbacv1alpha1.RBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: binding.Name, Namespace: namespace}, &updated); err != nil {
				return nil, err
			}
			out := map[string]metav1.ConditionStatus{}
			for _, c := range updated.Status.Conditions {
				out[c.Type] = c.Status
			}
			return out, nil
		}

		Eventually(conditionsByType).Should(SatisfyAll(
			HaveKeyWithValue(ldaprbacv1alpha1.ConditionReady, metav1.ConditionFalse),
			HaveKeyWithValue(ldaprbacv1alpha1.ConditionGroupNotFound, metav1.ConditionTrue),
			HaveKeyWithValue(ldaprbacv1alpha1.ConditionDegraded, metav1.ConditionFalse),
		))

		var rb rbacv1.RoleBinding
		err := k8sClient.Get(ctx, client.ObjectKey{Name: binding.Name, Namespace: namespace}, &rb)
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "no RoleBinding should be created for an unresolved group")
	})

	It("leaves the managed RoleBinding's subjects untouched when the directory becomes unreachable", func() {
		const failsafeProvider = "corp-ad-failsafe"
		const failsafeBinding = "data-team-failsafe"

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
			rbacGroupBindingGrouper.clearForcedError(failsafeProvider)
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, provider))).To(Succeed())
			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{Name: failsafeProvider}, &ldaprbacv1alpha1.LDAPProvider{})
				return apierrors.IsNotFound(err)
			}).Should(BeTrue())
		})

		binding := &ldaprbacv1alpha1.RBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: failsafeBinding, Namespace: namespace},
			Spec: ldaprbacv1alpha1.RBACGroupBindingSpec{
				ProviderRef: failsafeProvider,
				GroupDN:     groupDN,
				RoleRef:     ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"},
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		wantSubjects := []rbacv1.Subject{
			{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: "alice"},
			{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: "bob"},
		}

		var rb rbacv1.RoleBinding
		subjectsOf := func() ([]rbacv1.Subject, error) {
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: failsafeBinding, Namespace: namespace}, &rb); err != nil {
				return nil, err
			}
			return rb.Subjects, nil
		}
		Eventually(subjectsOf).Should(ConsistOf(wantSubjects[0], wantSubjects[1]))

		rbacGroupBindingGrouper.setForcedError(failsafeProvider, errors.New("simulated ldap outage"))

		Eventually(func() (metav1.ConditionStatus, error) {
			var updated ldaprbacv1alpha1.RBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: failsafeBinding, Namespace: namespace}, &updated); err != nil {
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
		Consistently(subjectsOf, "3s").Should(ConsistOf(wantSubjects[0], wantSubjects[1]))
	})
})
