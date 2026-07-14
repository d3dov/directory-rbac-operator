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

	// ActiveDirectory switches group-membership queries to AD's
	// LDAP_MATCHING_RULE_IN_CHAIN so nested group membership resolves
	// server-side.
	// +kubebuilder:default=false
	ActiveDirectory bool `json:"activeDirectory,omitempty"`
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
