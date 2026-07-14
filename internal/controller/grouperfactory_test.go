package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	ldaprbacv1alpha1 "github.com/d3dov/directory-rbac-operator/api/v1alpha1"
	"github.com/d3dov/directory-rbac-operator/internal/ldapclient"
)

// generateSelfSignedCertPEM returns a throwaway self-signed certificate,
// PEM-encoded the same way a real CA bundle Secret would hold one.
func generateSelfSignedCertPEM(t *testing.T) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}
	if err := ldaprbacv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add ldaprbac scheme: %v", err)
	}
	return scheme
}

func baseProvider() *ldaprbacv1alpha1.LDAPProvider {
	return &ldaprbacv1alpha1.LDAPProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "corp"},
		Spec: ldaprbacv1alpha1.LDAPProviderSpec{
			URL:               "ldap://directory.corp.local:389",
			BindDN:            "cn=svc,dc=corp,dc=local",
			InsecureSkipTLS:   true,
			UserSearchBase:    "ou=people,dc=corp,dc=local",
			GroupSearchBase:   "ou=groups,dc=corp,dc=local",
			UsernameAttribute: "uid",
			BindPasswordSecretRef: ldaprbacv1alpha1.SecretKeyRef{
				Name: "bind-credentials", Key: "password",
			},
		},
	}
}

func TestGrouperFactoryBuildsClientFromSecret(t *testing.T) {
	scheme := newTestScheme(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bind-credentials", Namespace: testSecretNamespace},
		Data:       map[string][]byte{"password": []byte("s3cret")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	f := &GrouperFactory{Client: c, SecretNamespace: testSecretNamespace, Limiters: &ldapclient.Limiters{}}

	if _, err := f.Grouper(context.Background(), baseProvider()); err != nil {
		t.Fatalf("Grouper() error = %v, want nil", err)
	}
	if _, err := f.Pinger(context.Background(), baseProvider()); err != nil {
		t.Fatalf("Pinger() error = %v, want nil", err)
	}
}

func TestGrouperFactoryErrorsWhenBindPasswordSecretMissing(t *testing.T) {
	scheme := newTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	f := &GrouperFactory{Client: c, SecretNamespace: testSecretNamespace}

	_, err := f.Grouper(context.Background(), baseProvider())
	if err == nil {
		t.Fatal("Grouper() error = nil, want an error when the bind password secret is missing")
	}
	if !strings.Contains(err.Error(), "bind password secret") {
		t.Fatalf("Grouper() error = %q, want it to mention the bind password secret", err.Error())
	}
}

func TestGrouperFactoryErrorsWhenBindPasswordKeyMissing(t *testing.T) {
	scheme := newTestScheme(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bind-credentials", Namespace: testSecretNamespace},
		Data:       map[string][]byte{"wrong-key": []byte("s3cret")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	f := &GrouperFactory{Client: c, SecretNamespace: testSecretNamespace}

	_, err := f.Grouper(context.Background(), baseProvider())
	if err == nil {
		t.Fatal("Grouper() error = nil, want an error when the bind password key is missing from the secret")
	}
}

func TestGrouperFactoryBuildsTLSConfigFromCASecret(t *testing.T) {
	scheme := newTestScheme(t)
	caPEM := generateSelfSignedCertPEM(t)
	bindSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bind-credentials", Namespace: testSecretNamespace},
		Data:       map[string][]byte{"password": []byte("s3cret")},
	}
	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca-bundle", Namespace: testSecretNamespace},
		Data:       map[string][]byte{"ca.crt": caPEM},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindSecret, caSecret).Build()
	f := &GrouperFactory{Client: c, SecretNamespace: testSecretNamespace}

	provider := baseProvider()
	provider.Spec.TLSConfig = &ldaprbacv1alpha1.TLSConfig{
		CASecretRef: &ldaprbacv1alpha1.SecretKeyRef{Name: "ca-bundle", Key: "ca.crt"},
	}

	if _, err := f.Grouper(context.Background(), provider); err != nil {
		t.Fatalf("Grouper() error = %v, want nil", err)
	}
}

func TestGrouperFactoryErrorsWhenCASecretMissing(t *testing.T) {
	scheme := newTestScheme(t)
	bindSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bind-credentials", Namespace: testSecretNamespace},
		Data:       map[string][]byte{"password": []byte("s3cret")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindSecret).Build()
	f := &GrouperFactory{Client: c, SecretNamespace: testSecretNamespace}

	provider := baseProvider()
	provider.Spec.TLSConfig = &ldaprbacv1alpha1.TLSConfig{
		CASecretRef: &ldaprbacv1alpha1.SecretKeyRef{Name: "missing", Key: "ca.crt"},
	}

	_, err := f.Grouper(context.Background(), provider)
	if err == nil {
		t.Fatal("Grouper() error = nil, want an error when the CA secret is missing")
	}
	if !strings.Contains(err.Error(), "ca bundle secret") {
		t.Fatalf("Grouper() error = %q, want it to mention the ca bundle secret", err.Error())
	}
}

func TestGrouperFactoryErrorsOnInvalidCAPEM(t *testing.T) {
	scheme := newTestScheme(t)
	bindSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bind-credentials", Namespace: testSecretNamespace},
		Data:       map[string][]byte{"password": []byte("s3cret")},
	}
	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca-bundle", Namespace: testSecretNamespace},
		Data:       map[string][]byte{"ca.crt": []byte("not a certificate")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindSecret, caSecret).Build()
	f := &GrouperFactory{Client: c, SecretNamespace: testSecretNamespace}

	provider := baseProvider()
	provider.Spec.TLSConfig = &ldaprbacv1alpha1.TLSConfig{
		CASecretRef: &ldaprbacv1alpha1.SecretKeyRef{Name: "ca-bundle", Key: "ca.crt"},
	}

	_, err := f.Grouper(context.Background(), provider)
	if err == nil {
		t.Fatal("Grouper() error = nil, want an error when the CA secret has no valid PEM certificates")
	}
	if !strings.Contains(err.Error(), "no valid PEM certificates") {
		t.Fatalf("Grouper() error = %q, want it to mention invalid PEM content", err.Error())
	}
}
