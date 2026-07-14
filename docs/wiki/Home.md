# directory-rbac-operator

`directory-rbac-operator` synchronizes membership from LDAP directories into
Kubernetes `RoleBinding` and `ClusterRoleBinding` resources. It manages
authorization only: use an OIDC provider such as Dex or Keycloak for
authentication.

Start with the repository [README](../../README.md) for the OpenLDAP
quickstart, then use these pages for operations and backend-specific details.

- [Architecture](Architecture)
- [Installation](Installation)
- [Directory backends](Directory-Backends)
- [CRD reference](CRD-Reference)
- [Troubleshooting](Troubleshooting)
- [Security](Security)
- [FAQ](FAQ)
- [Roadmap](Roadmap)
