package controller

import (
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
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

		Eventually(func() ([]corev1.Event, error) {
			var events corev1.EventList
			if err := k8sClient.List(ctx, &events, client.InNamespace(namespace)); err != nil {
				return nil, err
			}
			var matched []corev1.Event
			for _, e := range events.Items {
				if e.InvolvedObject.Name == bindingName && e.Reason == "RoleBindingCreated" {
					matched = append(matched, e)
				}
			}
			return matched, nil
		}).ShouldNot(BeEmpty(), "expected a RoleBindingCreated event on the binding")
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

	It("marks Degraded when the referenced LDAPProvider does not exist", func() {
		binding := &ldaprbacv1alpha1.RBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "no-such-provider-binding", Namespace: namespace},
			Spec: ldaprbacv1alpha1.RBACGroupBindingSpec{
				ProviderRef: "no-such-provider",
				GroupDN:     groupDN,
				RoleRef:     ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "view"},
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		Eventually(func() (metav1.ConditionStatus, error) {
			var updated ldaprbacv1alpha1.RBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: binding.Name, Namespace: namespace}, &updated); err != nil {
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
		const queryErrGroupDN = "cn=query-error,ou=groups,dc=corp,dc=local"

		rbacGroupBindingGrouper.setForcedGroupError(queryErrGroupDN, errors.New("simulated query failure"))
		DeferCleanup(func() { rbacGroupBindingGrouper.clearForcedGroupError(queryErrGroupDN) })

		binding := &ldaprbacv1alpha1.RBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "query-error-binding", Namespace: namespace},
			Spec: ldaprbacv1alpha1.RBACGroupBindingSpec{
				ProviderRef: providerName,
				GroupDN:     queryErrGroupDN,
				RoleRef:     ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "view"},
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		Eventually(func() (map[string]metav1.ConditionStatus, error) {
			var updated ldaprbacv1alpha1.RBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: binding.Name, Namespace: namespace}, &updated); err != nil {
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

	It("sets an owner reference on the managed RoleBinding pointing back at the binding", func() {
		const ownerRefBindingName = "data-team-ownerref"

		binding := &ldaprbacv1alpha1.RBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: ownerRefBindingName, Namespace: namespace},
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
			return k8sClient.Get(ctx, client.ObjectKey{Name: ownerRefBindingName, Namespace: namespace}, &rb)
		}).Should(Succeed())

		Expect(rb.OwnerReferences).To(ConsistOf(metav1.OwnerReference{
			APIVersion:         ldaprbacv1alpha1.GroupVersion.String(),
			Kind:               "RBACGroupBinding",
			Name:               binding.Name,
			UID:                binding.UID,
			Controller:         ptrTo(true),
			BlockOwnerDeletion: ptrTo(true),
		}))
	})

	It("deletes and recreates the RoleBinding when spec.roleRef changes, since RoleRef is immutable", func() {
		const roleRefChangeBindingName = "data-team-rolerefchange"

		binding := &ldaprbacv1alpha1.RBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: roleRefChangeBindingName, Namespace: namespace},
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
		Eventually(func() (rbacv1.RoleRef, error) {
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: roleRefChangeBindingName, Namespace: namespace}, &rb); err != nil {
				return rbacv1.RoleRef{}, err
			}
			return rb.RoleRef, nil
		}).Should(Equal(rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "edit"}))
		originalUID := rb.UID

		Eventually(func() error {
			var updated ldaprbacv1alpha1.RBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: roleRefChangeBindingName, Namespace: namespace}, &updated); err != nil {
				return err
			}
			updated.Spec.RoleRef = ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "view"}
			return k8sClient.Update(ctx, &updated)
		}).Should(Succeed())

		Eventually(func() (rbacv1.RoleRef, error) {
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: roleRefChangeBindingName, Namespace: namespace}, &rb); err != nil {
				return rbacv1.RoleRef{}, err
			}
			return rb.RoleRef, nil
		}).Should(Equal(rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"}))

		Expect(rb.UID).NotTo(Equal(originalUID), "expected a new object (delete+recreate), not an in-place update")
	})

	It("re-reconciles a binding when its LDAPProvider changes, without waiting for syncInterval", func() {
		const cascadeProvider = "corp-ad-cascade"
		const cascadeBinding = "data-team-cascade"

		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: cascadeProvider},
			Spec: ldaprbacv1alpha1.LDAPProviderSpec{
				URL:                   "ldaps://ad.corp.local:636",
				BindDN:                "cn=svc,dc=corp,dc=local",
				BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: "ldap-bind", Key: "password"},
				UserSearchBase:        "ou=people,dc=corp,dc=local",
				GroupSearchBase:       "ou=groups,dc=corp,dc=local",
				SyncInterval:          metav1.Duration{Duration: time.Hour},
				UsernameAttribute:     "uid",
			},
		}
		Expect(k8sClient.Create(ctx, provider)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, provider))).To(Succeed())
			Eventually(func() bool {
				return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKey{Name: cascadeProvider}, &ldaprbacv1alpha1.LDAPProvider{}))
			}).Should(BeTrue())
		})

		binding := &ldaprbacv1alpha1.RBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: cascadeBinding, Namespace: namespace},
			Spec: ldaprbacv1alpha1.RBACGroupBindingSpec{
				ProviderRef: cascadeProvider,
				GroupDN:     groupDN,
				RoleRef:     ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"},
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		var firstSync time.Time
		Eventually(func() (bool, error) {
			var updated ldaprbacv1alpha1.RBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: cascadeBinding, Namespace: namespace}, &updated); err != nil {
				return false, err
			}
			if updated.Status.LastSyncTime == nil {
				return false, nil
			}
			firstSync = updated.Status.LastSyncTime.Time
			return true, nil
		}).Should(BeTrue())

		// metav1.Time truncates to whole seconds, so without this gap a
		// same-second re-sync would be indistinguishable from no re-sync at
		// all.
		time.Sleep(1100 * time.Millisecond)

		// Touch the provider - the binding's own syncInterval is an hour, so
		// noticing this at all within the test's timeout proves the
		// provider-watch cascade fired rather than a coincidental timer.
		Eventually(func() error {
			var p ldaprbacv1alpha1.LDAPProvider
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: cascadeProvider}, &p); err != nil {
				return err
			}
			if p.Annotations == nil {
				p.Annotations = map[string]string{}
			}
			p.Annotations["ldaprbac.io/test-touch"] = "1"
			return k8sClient.Update(ctx, &p)
		}).Should(Succeed())

		Eventually(func() (time.Time, error) {
			var updated ldaprbacv1alpha1.RBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: cascadeBinding, Namespace: namespace}, &updated); err != nil {
				return time.Time{}, err
			}
			if updated.Status.LastSyncTime == nil {
				return time.Time{}, nil
			}
			return updated.Status.LastSyncTime.Time, nil
		}, "5s").Should(BeTemporally(">", firstSync))
	})

	It("re-reconciles a binding when its LDAPProvider's bind Secret is rotated, without waiting for syncInterval", func() {
		const secretName = "ldap-bind-rotation" //nolint:gosec // false positive: a Secret's object name, not a credential value
		const rotationProvider = "corp-ad-rotation"
		const rotationBinding = "data-team-rotation"

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
			StringData: map[string]string{"password": "initial"},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, secret))).To(Succeed())
		})

		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: rotationProvider},
			Spec: ldaprbacv1alpha1.LDAPProviderSpec{
				URL:                   "ldaps://ad.corp.local:636",
				BindDN:                "cn=svc,dc=corp,dc=local",
				BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: secretName, Key: "password"},
				UserSearchBase:        "ou=people,dc=corp,dc=local",
				GroupSearchBase:       "ou=groups,dc=corp,dc=local",
				SyncInterval:          metav1.Duration{Duration: time.Hour},
				UsernameAttribute:     "uid",
			},
		}
		Expect(k8sClient.Create(ctx, provider)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, provider))).To(Succeed())
			Eventually(func() bool {
				return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKey{Name: rotationProvider}, &ldaprbacv1alpha1.LDAPProvider{}))
			}).Should(BeTrue())
		})

		binding := &ldaprbacv1alpha1.RBACGroupBinding{
			ObjectMeta: metav1.ObjectMeta{Name: rotationBinding, Namespace: namespace},
			Spec: ldaprbacv1alpha1.RBACGroupBindingSpec{
				ProviderRef: rotationProvider,
				GroupDN:     groupDN,
				RoleRef:     ldaprbacv1alpha1.RoleRef{Kind: "ClusterRole", Name: "edit"},
			},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed())
		})

		var firstSync time.Time
		Eventually(func() (bool, error) {
			var updated ldaprbacv1alpha1.RBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: rotationBinding, Namespace: namespace}, &updated); err != nil {
				return false, err
			}
			if updated.Status.LastSyncTime == nil {
				return false, nil
			}
			firstSync = updated.Status.LastSyncTime.Time
			return true, nil
		}).Should(BeTrue())

		// metav1.Time truncates to whole seconds, so without this gap a
		// same-second re-sync would be indistinguishable from no re-sync at
		// all.
		time.Sleep(1100 * time.Millisecond)

		Eventually(func() error {
			var s corev1.Secret
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: secretName, Namespace: namespace}, &s); err != nil {
				return err
			}
			s.StringData = map[string]string{"password": "rotated"}
			return k8sClient.Update(ctx, &s)
		}).Should(Succeed())

		Eventually(func() (time.Time, error) {
			var updated ldaprbacv1alpha1.RBACGroupBinding
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: rotationBinding, Namespace: namespace}, &updated); err != nil {
				return time.Time{}, err
			}
			if updated.Status.LastSyncTime == nil {
				return time.Time{}, nil
			}
			return updated.Status.LastSyncTime.Time, nil
		}, "5s").Should(BeTemporally(">", firstSync))
	})
})

func ptrTo[T any](v T) *T { return &v }
