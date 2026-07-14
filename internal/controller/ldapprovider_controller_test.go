package controller

import (
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
)

var _ = Describe("LDAPProviderReconciler", func() {
	readyCondition := func(name string) func() (metav1.ConditionStatus, error) {
		return func() (metav1.ConditionStatus, error) {
			var provider ldaprbacv1alpha1.LDAPProvider
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &provider); err != nil {
				return "", err
			}
			for _, c := range provider.Status.Conditions {
				if c.Type == ldaprbacv1alpha1.ConditionReady {
					return c.Status, nil
				}
			}
			return "", nil
		}
	}

	It("marks a valid ldaps:// provider Ready once the bind check succeeds", func() {
		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "corp-ad-valid"},
			Spec: ldaprbacv1alpha1.LDAPProviderSpec{
				URL:                   "ldaps://ad.corp.local:636",
				BindDN:                "cn=svc,dc=corp,dc=local",
				BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "ldap-bind", Key: "password"},
				UserSearchBase:        "ou=people,dc=corp,dc=local",
				GroupSearchBase:       "ou=groups,dc=corp,dc=local",
				SyncInterval:          metav1.Duration{Duration: time.Minute},
			},
		}
		Expect(k8sClient.Create(ctx, provider)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, provider))).To(Succeed())
		})

		Eventually(readyCondition(provider.Name)).Should(Equal(metav1.ConditionTrue))
	})

	It("rejects a plain ldap:// provider with neither insecureSkipTLS nor a CA secret", func() {
		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "corp-ad-ambiguous-tls"},
			Spec: ldaprbacv1alpha1.LDAPProviderSpec{
				URL:                   "ldap://ad.corp.local:389",
				BindDN:                "cn=svc,dc=corp,dc=local",
				BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "ldap-bind", Key: "password"},
				UserSearchBase:        "ou=people,dc=corp,dc=local",
				GroupSearchBase:       "ou=groups,dc=corp,dc=local",
				SyncInterval:          metav1.Duration{Duration: time.Minute},
			},
		}
		Expect(k8sClient.Create(ctx, provider)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, provider))).To(Succeed())
		})

		Eventually(readyCondition(provider.Name)).Should(Equal(metav1.ConditionFalse))

		var updated ldaprbacv1alpha1.LDAPProvider
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: provider.Name}, &updated)).To(Succeed())
		for _, c := range updated.Status.Conditions {
			if c.Type == ldaprbacv1alpha1.ConditionReady {
				Expect(c.Reason).To(Equal(ldaprbacv1alpha1.ReasonInvalidSpec))
			}
		}
	})

	It("accepts a plain ldap:// provider with insecureSkipTLS: true", func() {
		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "corp-ad-insecure-skip-tls"},
			Spec: ldaprbacv1alpha1.LDAPProviderSpec{
				URL:                   "ldap://ad.corp.local:389",
				BindDN:                "cn=svc,dc=corp,dc=local",
				BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "ldap-bind", Key: "password"},
				InsecureSkipTLS:       true,
				UserSearchBase:        "ou=people,dc=corp,dc=local",
				GroupSearchBase:       "ou=groups,dc=corp,dc=local",
				SyncInterval:          metav1.Duration{Duration: time.Minute},
			},
		}
		Expect(k8sClient.Create(ctx, provider)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, provider))).To(Succeed())
		})

		Eventually(readyCondition(provider.Name)).Should(Equal(metav1.ConditionTrue))
	})

	It("accepts a plain ldap:// provider with a CA secret configured for StartTLS", func() {
		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "corp-ad-starttls"},
			Spec: ldaprbacv1alpha1.LDAPProviderSpec{
				URL:                   "ldap://ad.corp.local:389",
				BindDN:                "cn=svc,dc=corp,dc=local",
				BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "ldap-bind", Key: "password"},
				TLSConfig: &ldaprbacv1alpha1.TLSConfig{
					CASecretRef: &ldaprbacv1alpha1.SecretKeyRef{Name: "ldap-ca", Key: "ca.crt"},
				},
				UserSearchBase:    "ou=people,dc=corp,dc=local",
				GroupSearchBase:   "ou=groups,dc=corp,dc=local",
				SyncInterval:      metav1.Duration{Duration: time.Minute},
				UsernameAttribute: "uid",
			},
		}
		Expect(k8sClient.Create(ctx, provider)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, provider))).To(Succeed())
		})

		Eventually(readyCondition(provider.Name)).Should(Equal(metav1.ConditionTrue))
	})

	It("deletes the provider's rate limiter once it finishes deleting", func() {
		const provName = "corp-ad-limiter-cleanup"

		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: provName},
			Spec: ldaprbacv1alpha1.LDAPProviderSpec{
				URL:                   "ldaps://ad.corp.local:636",
				BindDN:                "cn=svc,dc=corp,dc=local",
				BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "ldap-bind", Key: "password"},
				UserSearchBase:        "ou=people,dc=corp,dc=local",
				GroupSearchBase:       "ou=groups,dc=corp,dc=local",
				SyncInterval:          metav1.Duration{Duration: time.Minute},
			},
		}
		Expect(k8sClient.Create(ctx, provider)).To(Succeed())

		Eventually(func() ([]string, error) {
			var p ldaprbacv1alpha1.LDAPProvider
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: provName}, &p); err != nil {
				return nil, err
			}
			return p.Finalizers, nil
		}).Should(ContainElement("ldaprbac.io/in-use-protection"))

		// Get() creates the entry on first use; its identity afterward
		// proves whether finalize() actually deleted it (Delete+Get would
		// hand back a new, distinct *rate.Limiter) or left it in place.
		before := ldapProviderLimiters.Get(provName)

		Expect(k8sClient.Delete(ctx, provider)).To(Succeed())
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKey{Name: provName}, &ldaprbacv1alpha1.LDAPProvider{}))
		}).Should(BeTrue())

		Expect(ldapProviderLimiters.Get(provName)).NotTo(BeIdenticalTo(before), "expected finalize() to delete the provider's limiter entry")
	})

	It("marks Degraded when the bind check fails", func() {
		const provName = "corp-ad-bind-failure"

		ldapProviderPinger.setForcedError(provName, errors.New("simulated bind failure"))
		DeferCleanup(func() { ldapProviderPinger.clearForcedError(provName) })

		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: provName},
			Spec: ldaprbacv1alpha1.LDAPProviderSpec{
				URL:                   "ldaps://ad.corp.local:636",
				BindDN:                "cn=svc,dc=corp,dc=local",
				BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "ldap-bind", Key: "password"},
				UserSearchBase:        "ou=people,dc=corp,dc=local",
				GroupSearchBase:       "ou=groups,dc=corp,dc=local",
				SyncInterval:          metav1.Duration{Duration: time.Minute},
			},
		}
		Expect(k8sClient.Create(ctx, provider)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, provider))).To(Succeed())
		})

		Eventually(readyCondition(provider.Name)).Should(Equal(metav1.ConditionFalse))

		var updated ldaprbacv1alpha1.LDAPProvider
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: provider.Name}, &updated)).To(Succeed())
		for _, c := range updated.Status.Conditions {
			if c.Type == ldaprbacv1alpha1.ConditionDegraded {
				Expect(c.Status).To(Equal(metav1.ConditionTrue))
				Expect(c.Reason).To(Equal(ldaprbacv1alpha1.ReasonLDAPUnreachable))
			}
		}
	})

	It("blocks deletion while a binding still references the provider, then clears once it doesn't", func() {
		const provName = "corp-ad-in-use"
		const bindingName3 = "data-team-in-use"

		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: provName},
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

		binding := &ldaprbacv1alpha1.RBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: bindingName3, Namespace: "default"},
			Spec: ldaprbacv1alpha1.RBACGroupBindingSpec{
				ProviderRef: provName,
				GroupDN:     "cn=data-team,ou=groups,dc=corp,dc=local",
				RoleRef:     ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"},
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())

		// Wait for the in-use-protection finalizer to actually be attached
		// before triggering deletion, or the delete below could race the
		// reconcile that adds it.
		Eventually(func() ([]string, error) {
			var p ldaprbacv1alpha1.LDAPProvider
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: provName}, &p); err != nil {
				return nil, err
			}
			return p.Finalizers, nil
		}).Should(ContainElement("ldaprbac.io/in-use-protection"))

		Expect(k8sClient.Delete(ctx, provider)).To(Succeed())

		Consistently(func() ([]string, error) {
			var p ldaprbacv1alpha1.LDAPProvider
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: provName}, &p); err != nil {
				return nil, err
			}
			return p.Finalizers, nil
		}, "1s").Should(ContainElement("ldaprbac.io/in-use-protection"), "deletion should stay blocked while the binding still references it")

		Expect(k8sClient.Delete(ctx, binding)).To(Succeed())

		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKey{Name: provName}, &ldaprbacv1alpha1.LDAPProvider{}))
		}).Should(BeTrue(), "provider should finish deleting once its last dependent is gone")
	})
})
