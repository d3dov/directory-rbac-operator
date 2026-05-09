package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterRBACGroupBindingSpec maps an LDAP/AD group onto a ClusterRoleBinding.
type ClusterRBACGroupBindingSpec struct {
	// ProviderRef names the LDAPProvider this binding resolves membership
	// against.
	ProviderRef string `json:"providerRef"`

	// GroupDN is the distinguished name of the source group.
	GroupDN string `json:"groupDN"`

	// ClusterRoleRef names the ClusterRole the managed ClusterRoleBinding
	// grants. A ClusterRoleBinding's roleRef.kind is always ClusterRole (the
	// API server enforces this), so unlike RBACGroupBinding.spec.roleRef
	// there is no separate Kind field to specify.
	ClusterRoleRef string `json:"clusterRoleRef"`
}

// ClusterRBACGroupBindingStatus reports the last observed sync result.
type ClusterRBACGroupBindingStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// +optional
	MemberCount int32 `json:"memberCount,omitempty"`

	// +optional
	MembersPreview []string `json:"membersPreview,omitempty"`

	// +optional
	MembersTruncated bool `json:"membersTruncated,omitempty"`

	// +optional
	MembersHash string `json:"membersHash,omitempty"`

	// ClusterRoleBindingRef names the ClusterRoleBinding this binding
	// manages.
	// +optional
	ClusterRoleBindingRef *corev1.LocalObjectReference `json:"clusterRoleBindingRef,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=crgb,categories=ldaprbac
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=".spec.providerRef"
// +kubebuilder:printcolumn:name="Group",type=string,JSONPath=".spec.groupDN"
// +kubebuilder:printcolumn:name="ClusterRole",type=string,JSONPath=".spec.clusterRoleRef"
// +kubebuilder:printcolumn:name="Members",type=integer,JSONPath=".status.memberCount"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=".status.lastSyncTime"

// ClusterRBACGroupBinding maps an LDAP/AD group to a ClusterRole by
// continuously reconciling a ClusterRoleBinding's subjects to the group's
// membership.
type ClusterRBACGroupBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterRBACGroupBindingSpec   `json:"spec"`
	Status ClusterRBACGroupBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterRBACGroupBindingList contains a list of ClusterRBACGroupBinding.
type ClusterRBACGroupBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterRBACGroupBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterRBACGroupBinding{}, &ClusterRBACGroupBindingList{})
}
