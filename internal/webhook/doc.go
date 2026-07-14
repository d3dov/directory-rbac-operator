// Package webhook validates RBACGroupBinding and ClusterRBACGroupBinding
// admission, rejecting a group-to-role mapping that duplicates one another
// binding of the same kind already manages in the same scope (namespace for
// RBACGroupBinding, cluster-wide for ClusterRBACGroupBinding). Two bindings
// mapping the same group to the same role would each independently
// reconcile their own, differently-named managed object with identical
// subjects and permissions - never useful, and far more likely a copy-paste
// mistake than intent.
//
// This is admission-time validation, not something the CRD schema alone can
// express: rejecting it requires listing sibling objects, which
// +kubebuilder:validation:XValidation CEL rules (scoped to a single object)
// cannot do. Compare LDAPProviderSpec.DirectoryType, a plain enum with no
// cross-object dependency, which is validated via a CRD schema marker
// instead of a webhook for exactly that reason.
package webhook
