package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ldaprbacv1alpha1 "github.com/denis-da-engineer/directory-rbac-operator/api/v1alpha1"
	"github.com/denis-da-engineer/directory-rbac-operator/internal/ldapclient"
)

// GrouperResolver turns an LDAPProvider into something that can answer group
// membership queries. Production wiring uses GrouperFactory; tests inject a
// stub backed by ldapclient/fake so envtest specs never need a real
// directory server.
type GrouperResolver interface {
	Grouper(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (ldapclient.Grouper, error)
}

// PingerResolver turns an LDAPProvider into something that can verify
// connectivity/bind credentials. Backs the LDAPProviderReconciler health
// check the same way GrouperResolver backs the binding reconcilers.
type PingerResolver interface {
	Pinger(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (ldapclient.Pinger, error)
}

// GrouperFactory builds a real ldapclient.Client per LDAPProvider, resolving
// its bind password (and CA bundle, if configured) from Secrets in
// SecretNamespace - LDAPProvider is cluster-scoped and so has no namespace of
// its own to read Secrets from. The same *ldapclient.Client satisfies both
// Grouper and Pinger, so Grouper and Pinger just build one and return it as
// whichever interface the caller asked for.
type GrouperFactory struct {
	Client          client.Client
	SecretNamespace string

	// Limiters, if set, shares one rate limiter per provider name across
	// every Client built for it - the health check and every binding
	// reconciling against the same directory all draw from the same
	// budget. Nil disables rate limiting entirely.
	Limiters *ldapclient.Limiters
}

var (
	_ GrouperResolver = (*GrouperFactory)(nil)
	_ PingerResolver  = (*GrouperFactory)(nil)
)

// Grouper implements GrouperResolver.
func (f *GrouperFactory) Grouper(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (ldapclient.Grouper, error) {
	return f.client(ctx, provider)
}

// Pinger implements PingerResolver.
func (f *GrouperFactory) Pinger(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (ldapclient.Pinger, error) {
	return f.client(ctx, provider)
}

func (f *GrouperFactory) client(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (*ldapclient.Client, error) {
	password, err := f.secretValue(ctx, provider.Spec.BindPasswordSecretRef)
	if err != nil {
		return nil, fmt.Errorf("bind password secret: %w", err)
	}

	tlsConfig, err := f.tlsConfig(ctx, provider)
	if err != nil {
		return nil, err
	}

	var limiter *rate.Limiter
	if f.Limiters != nil {
		limiter = f.Limiters.Get(provider.Name)
	}

	return ldapclient.New(ldapclient.Config{
		URL:               provider.Spec.URL,
		BindDN:            provider.Spec.BindDN,
		BindPassword:      password,
		InsecureSkipTLS:   provider.Spec.InsecureSkipTLS,
		TLSConfig:         tlsConfig,
		UserSearchBase:    provider.Spec.UserSearchBase,
		GroupSearchBase:   provider.Spec.GroupSearchBase,
		UsernameAttribute: provider.Spec.UsernameAttribute,
		Limiter:           limiter,
	}), nil
}

func (f *GrouperFactory) tlsConfig(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (*tls.Config, error) {
	if provider.Spec.TLSConfig == nil || provider.Spec.TLSConfig.CASecretRef == nil {
		return nil, nil
	}

	caPEM, err := f.secretValue(ctx, *provider.Spec.TLSConfig.CASecretRef)
	if err != nil {
		return nil, fmt.Errorf("ca bundle secret: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		ref := provider.Spec.TLSConfig.CASecretRef
		return nil, fmt.Errorf("ca bundle secret %s/%s: no valid PEM certificates found", f.SecretNamespace, ref.Name)
	}
	return &tls.Config{RootCAs: pool}, nil
}

func (f *GrouperFactory) secretValue(ctx context.Context, ref ldaprbacv1alpha1.SecretKeyRef) (string, error) {
	var secret corev1.Secret
	if err := f.Client.Get(ctx, client.ObjectKey{Namespace: f.SecretNamespace, Name: ref.Name}, &secret); err != nil {
		return "", err
	}

	value, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", ref.Key, f.SecretNamespace, ref.Name)
	}
	return string(value), nil
}
