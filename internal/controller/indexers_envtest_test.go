package controller

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
)

var _ = Describe("secretRefIndexField", func() {
	// The bind-password half of this index is exercised by the
	// RBACGroupBindingReconciler suite's secret-rotation-cascade spec; this
	// covers the other half - an LDAPProvider indexed under its
	// TLSConfig.caSecretRef name too, not just its bind password secret -
	// which nothing else in this suite creates a provider with.
	It("re-reconciles a binding when its LDAPProvider's CA bundle Secret is rotated, without waiting for syncInterval", func() {
		//nolint:gosec // false positive: Secret object names, not credential values
		const (
			namespace        = "default"
			bindSecretName   = "ldap-bind-ca-indexed"
			caSecretName     = "ldap-ca-bundle-rotation"
			rotationProvider = "corp-ad-ca-indexed"
			rotationBinding  = "data-team-ca-rotation"
			groupDN          = "cn=data-team,ou=groups,dc=corp,dc=local"
		)

		bindSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: bindSecretName, Namespace: namespace},
			StringData: map[string]string{"password": "s3cret"},
		}
		Expect(k8sClient.Create(ctx, bindSecret)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, bindSecret))).To(Succeed())
		})

		caSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: caSecretName, Namespace: namespace},
			StringData: map[string]string{"ca.crt": "initial"},
		}
		Expect(k8sClient.Create(ctx, caSecret)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, caSecret))).To(Succeed())
		})

		provider := &ldaprbacv1alpha1.LDAPProvider{
			ObjectMeta: metav1.ObjectMeta{Name: rotationProvider},
			Spec: ldaprbacv1alpha1.LDAPProviderSpec{
				URL:                   "ldaps://ad.corp.local:636",
				BindDN:                "cn=svc,dc=corp,dc=local",
				BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{Name: bindSecretName, Key: "password"},
				TLSConfig: &ldaprbacv1alpha1.TLSConfig{
					CASecretRef: &ldaprbacv1alpha1.SecretKeyRef{Name: caSecretName, Key: "ca.crt"},
				},
				UserSearchBase:    "ou=people,dc=corp,dc=local",
				GroupSearchBase:   "ou=groups,dc=corp,dc=local",
				SyncInterval:      metav1.Duration{Duration: time.Hour},
				UsernameAttribute: "uid",
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
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: caSecretName, Namespace: namespace}, &s); err != nil {
				return err
			}
			s.StringData = map[string]string{"ca.crt": "rotated"}
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
