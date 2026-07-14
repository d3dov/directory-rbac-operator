// Package v1alpha1 contains the ldaprbac.io/v1alpha1 API group: LDAPProvider,
// RBACGroupBinding and ClusterRBACGroupBinding.
//
// +kubebuilder:object:generate=true
// +groupName=ldaprbac.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "ldaprbac.io", Version: "v1alpha1"}

	// SchemeBuilder collects the funcs that add this group-version's types to
	// a scheme. Built directly on apimachinery's runtime.SchemeBuilder rather
	// than controller-runtime's scheme.Builder helper, which is deprecated
	// for use in api packages precisely to keep them free of non-api,
	// non-stdlib dependencies.
	SchemeBuilder = &runtime.SchemeBuilder{}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion,
			&LDAPProvider{}, &LDAPProviderList{},
			&RBACGroupBinding{}, &RBACGroupBindingList{},
			&ClusterRBACGroupBinding{}, &ClusterRBACGroupBindingList{},
		)
		metav1.AddToGroupVersion(s, GroupVersion)
		return nil
	})
}
