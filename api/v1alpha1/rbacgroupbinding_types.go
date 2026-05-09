package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RoleRef names the Role or ClusterRole a namespaced binding grants.
type RoleRef struct {
	// +kubebuilder:validation:Enum=Role;ClusterRole
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// RBACGroupBindingSpec maps an LDAP/AD group onto a namespaced RoleBinding.
type RBACGroupBindingSpec struct {
	// ProviderRef names the LDAPProvider this binding resolves membership
	// against.
	ProviderRef string `json:"providerRef"`

	// GroupDN is the distinguished name of the source group.
	GroupDN string `json:"groupDN"`

	// RoleRef is the Role or ClusterRole the managed RoleBinding grants.
	RoleRef RoleRef `json:"roleRef"`
}

// RBACGroupBindingStatus reports the last observed sync result.
type RBACGroupBindingStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// MemberCount is the number of members resolved on the last successful
	// sync.
	// +optional
	MemberCount int32 `json:"memberCount,omitempty"`

	// MembersPreview is a capped, sorted sample of resolved member names, for
	// quick inspection without listing the managed RoleBinding.
	// +optional
	MembersPreview []string `json:"membersPreview,omitempty"`

	// MembersTruncated is true when MembersPreview omits members because the
	// full set exceeds the preview cap.
	// +optional
	MembersTruncated bool `json:"membersTruncated,omitempty"`

	// MembersHash is a hash of the full sorted member set, used internally to
	// detect drift without diffing large lists on every reconcile.
	// +optional
	MembersHash string `json:"membersHash,omitempty"`

	// RoleBindingRef names the RoleBinding this binding manages.
	// +optional
	RoleBindingRef *corev1.LocalObjectReference `json:"roleBindingRef,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=rgb,categories=ldaprbac
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=".spec.providerRef"
// +kubebuilder:printcolumn:name="Group",type=string,JSONPath=".spec.groupDN"
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=".spec.roleRef.name"
// +kubebuilder:printcolumn:name="Members",type=integer,JSONPath=".status.memberCount"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=".status.lastSyncTime"

// RBACGroupBinding maps an LDAP/AD group to a namespaced Role or ClusterRole
// by continuously reconciling a RoleBinding's subjects to the group's
// membership.
type RBACGroupBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RBACGroupBindingSpec   `json:"spec"`
	Status RBACGroupBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RBACGroupBindingList contains a list of RBACGroupBinding.
type RBACGroupBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RBACGroupBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RBACGroupBinding{}, &RBACGroupBindingList{})
}
