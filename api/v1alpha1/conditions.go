package v1alpha1

// Condition types reported on LDAPProvider, RBACGroupBinding and
// ClusterRBACGroupBinding status.
const (
	// ConditionReady means the last reconcile completed successfully: the
	// directory was reachable and, for bindings, the managed RoleBinding/
	// ClusterRoleBinding subjects match the resolved group membership.
	ConditionReady = "Ready"

	// ConditionDegraded means the directory could not be reached (or another
	// transient error occurred) and the object is serving its last known-good
	// state rather than the current one.
	ConditionDegraded = "Degraded"

	// ConditionGroupNotFound means the directory was reachable but groupDN
	// resolved to no entry. Like Degraded, existing RBAC subjects are left
	// untouched rather than cleared.
	ConditionGroupNotFound = "GroupNotFound"
)

// Condition reasons, paired with the condition types above.
const (
	ReasonSyncSucceeded   = "SyncSucceeded"
	ReasonLDAPUnreachable = "LDAPUnreachable"
	ReasonBindFailed      = "BindFailed"
	ReasonGroupNotFound   = "GroupNotFound"
	ReasonInvalidSpec     = "InvalidSpec"
)
