package controller

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
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
})
