package controller

import (
	"context"
	"fmt"

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

// GrouperFactory builds a real ldapclient.Client per LDAPProvider, resolving
// its bind password from a Secret in SecretNamespace - LDAPProvider is
// cluster-scoped and so has no namespace of its own to read Secrets from.
type GrouperFactory struct {
	Client          client.Client
	SecretNamespace string
}

var _ GrouperResolver = (*GrouperFactory)(nil)

func (f *GrouperFactory) Grouper(ctx context.Context, provider *ldaprbacv1alpha1.LDAPProvider) (ldapclient.Grouper, error) {
	password, err := f.secretValue(ctx, provider.Spec.BindPasswordSecretRef)
	if err != nil {
		return nil, fmt.Errorf("bind password secret: %w", err)
	}

	return ldapclient.New(ldapclient.Config{
		URL:               provider.Spec.URL,
		BindDN:            provider.Spec.BindDN,
		BindPassword:      password,
		InsecureSkipTLS:   provider.Spec.InsecureSkipTLS,
		UserSearchBase:    provider.Spec.UserSearchBase,
		GroupSearchBase:   provider.Spec.GroupSearchBase,
		UsernameAttribute: provider.Spec.UsernameAttribute,
	}), nil
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
