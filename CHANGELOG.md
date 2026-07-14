# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until the first tagged release, everything lives under `[Unreleased]`.

## [Unreleased]

### Added

- `LDAPProvider`, `RBACGroupBinding`, and `ClusterRBACGroupBinding` CRDs
  (`ldaprbac.io/v1alpha1`).
- LDAP/AD group membership resolution (`internal/ldapclient`): LDAPS and
  StartTLS, a reverse `memberOf` query with a fallback to the group's own
  `member`/`uniqueMember` attribute for directories without a `memberOf`
  overlay, and per-provider rate limiting shared across every consumer of a
  given directory.
- Reconcilers syncing `RBACGroupBinding` to a `RoleBinding` and
  `ClusterRBACGroupBinding` to a `ClusterRoleBinding`, including correct
  handling of `roleRef` immutability (delete-then-recreate) and
  owner-reference garbage collection.
- `LDAPProvider` health-check controller with a bind-only readiness check and
  an in-use-protection finalizer that blocks deletion while any binding
  still references it.
- Fail-safe behavior: an unreachable directory or an unresolved group DN
  never removes existing RBAC subjects, surfaced through `Ready`/`Degraded`/
  `GroupNotFound` status conditions and `kubectl` printcolumns.
- Kubernetes Events on every meaningful reconcile outcome.
- Prometheus metrics: `ldaprbac_sync_total`, `ldaprbac_sync_duration_seconds`,
  `ldaprbac_ldap_errors_total`, `ldaprbac_members_count`.
- Watches that cascade an `LDAPProvider` change or a bind-credential Secret
  rotation to dependent bindings immediately, instead of waiting for the
  next `syncInterval`.
- Helm chart: configurable RBAC strictness (`rbac.strict`), optional
  `ServiceMonitor`, leader election, and a metrics `Service`.
- Unit tests, wire-level `ldapclient` tests against an embedded LDAP server,
  `envtest`-based controller integration tests, and a `kind` +
  docker-compose OpenLDAP E2E workflow.
- GitHub Actions CI (build/vet/fmt/generated-artifact drift/unit+envtest,
  Helm lint) and a separate E2E workflow.

[Unreleased]: https://github.com/denis-da-engineer/directory-rbac-operator/commits/main
