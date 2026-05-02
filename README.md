# directory-rbac-operator

A Kubernetes operator that continuously syncs LDAP/Active Directory group
membership into `RoleBinding`/`ClusterRoleBinding` objects, declaratively,
through CRDs.

It handles authorization sync only — pair it with Dex/OIDC/kubelogin for
authentication.

Status: early development (M1/MVP in progress). Quickstart and usage docs
land once the basic reconcile loop is in place.
