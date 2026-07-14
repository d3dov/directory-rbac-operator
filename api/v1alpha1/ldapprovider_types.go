package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretKeyRef points at a single key within a Secret in the operator's
// configured secret namespace (see the --secret-namespace flag): LDAPProvider
// is cluster-scoped, so it cannot itself carry a Secret namespace.
type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// TLSConfig customizes certificate validation for ldaps:// and StartTLS
// connections. Leaving it unset validates against the system trust store.
type TLSConfig struct {
	// CASecretRef points at a PEM-encoded CA bundle used instead of (in
	// addition to) the system trust store.
	// +optional
	CASecretRef *SecretKeyRef `json:"caSecretRef,omitempty"`
}

// DirectoryType selects which directory backend a LDAPProvider talks to, so
// backend-specific behavior (paged results, referral chasing, nested-group
// resolution) is switched on an explicit, validated choice instead of being
// inferred from other settings or guessed at from server responses.
// +kubebuilder:validation:Enum=OpenLDAP;ActiveDirectory;FreeIPA
type DirectoryType string

const (
	// DirectoryTypeOpenLDAP is the default: no AD-specific extended controls
	// or matching rules are used. Nested-group membership is only as flat as
	// the server's own memberOf overlay (or lack of one) makes it.
	DirectoryTypeOpenLDAP DirectoryType = "OpenLDAP"

	// DirectoryTypeActiveDirectory enables AD-specific behavior: RFC 2696
	// paged results (AD caps unpaged searches at 1000 entries by default) and
	// the LDAP_MATCHING_RULE_IN_CHAIN OID for server-side nested-group
	// resolution.
	DirectoryTypeActiveDirectory DirectoryType = "ActiveDirectory"

	// DirectoryTypeFreeIPA targets a FreeIPA/389-ds server. 389-ds computes
	// memberOf recursively itself (see the MemberOf plugin), so a group's
	// memberOf-based membership is already flat; FreeIPA does not enable the
	// AD matching-rule branch and needs no separate recursive-query logic.
	DirectoryTypeFreeIPA DirectoryType = "FreeIPA"
)

// LDAPProviderSpec describes how to connect to and query an LDAP/AD
// directory.
type LDAPProviderSpec struct {
	// URL of the directory server, e.g. ldaps://ad.corp.local:636 or
	// ldap://ad.corp.local:389.
	// +kubebuilder:validation:Pattern=`^ldaps?://.+`
	URL string `json:"url"`

	// BindDN is the distinguished name the operator authenticates as.
	BindDN string `json:"bindDN"`

	// BindPasswordSecretRef holds the bind credential.
	BindPasswordSecretRef SecretKeyRef `json:"bindPasswordSecretRef"`

	// TLSConfig customizes CA validation for ldaps:// and StartTLS.
	// +optional
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`

	// InsecureSkipTLS allows a plaintext ldap:// bind with no StartTLS
	// upgrade. Must be set explicitly; there is no implicit plaintext
	// fallback.
	// +kubebuilder:default=false
	InsecureSkipTLS bool `json:"insecureSkipTLS,omitempty"`

	// UserSearchBase is the base DN under which user entries are searched.
	UserSearchBase string `json:"userSearchBase"`

	// GroupSearchBase is the base DN under which group entries are searched.
	GroupSearchBase string `json:"groupSearchBase"`

	// SyncInterval is how often bindings referencing this provider re-query
	// group membership.
	SyncInterval metav1.Duration `json:"syncInterval"`

	// UsernameAttribute is the user-entry attribute projected as the
	// rbacv1.Subject name for resolved members. It must match whatever the
	// cluster's OIDC/Dex layer presents as the authenticated username claim;
	// the operator has no visibility into that mapping, so this is
	// configurable rather than assumed. Common values: uid (POSIX/OpenLDAP),
	// sAMAccountName or userPrincipalName (Active Directory).
	// +kubebuilder:default="uid"
	UsernameAttribute string `json:"usernameAttribute,omitempty"`

	// DirectoryType picks the directory backend and, with it, the
	// backend-specific behavior described on the DirectoryType* constants.
	// Rejecting anything outside the enum keeps that switch explicit: a
	// typo'd or unsupported value fails validation instead of silently
	// falling back to OpenLDAP behavior against a server that isn't OpenLDAP.
	// +kubebuilder:default=OpenLDAP
	DirectoryType DirectoryType `json:"directoryType,omitempty"`
}

// LDAPProviderStatus reports the last observed health of the directory
// connection.
type LDAPProviderStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// +optional
	LastVerifiedTime *metav1.Time `json:"lastVerifiedTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=ldapp,categories=ldaprbac
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=".spec.url"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// LDAPProvider describes connection settings for an LDAP/Active Directory
// server used as a source of group membership.
type LDAPProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LDAPProviderSpec   `json:"spec"`
	Status LDAPProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// LDAPProviderList contains a list of LDAPProvider.
type LDAPProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LDAPProvider `json:"items"`
}
