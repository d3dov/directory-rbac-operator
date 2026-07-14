# Security

Bind credentials and CA bundles are referenced from Kubernetes Secrets. Keep
the operator's `secretNamespace` narrow; set `rbac.strict: true` to use a
namespaced Secret Role instead of the default cluster-wide Secret rule.

The chart runs as UID/GID 65532, forbids privilege escalation, drops Linux
capabilities, uses a read-only root filesystem, and selects the RuntimeDefault
seccomp profile. It also sets resource requests/limits and a PDB.

Use LDAPS or StartTLS in production. Plain LDAP is accepted only with an
explicit `insecureSkipTLS: true`, and should be limited to isolated test
environments. Review the `bind` permission required by the ServiceAccount:
Kubernetes requires it before a controller may bind a role it does not already
hold.

Release images are not Cosign-signed yet. Verify source and image provenance
according to your organization's policy until keyless signing is introduced.
