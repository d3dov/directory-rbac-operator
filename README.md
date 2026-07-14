# directory-rbac-operator

[![CI](https://github.com/d3dov/directory-rbac-operator/actions/workflows/ci.yaml/badge.svg)](https://github.com/d3dov/directory-rbac-operator/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/d3dov/directory-rbac-operator)](https://goreportcard.com/report/github.com/d3dov/directory-rbac-operator)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/d3dov/directory-rbac-operator)](https://github.com/d3dov/directory-rbac-operator/releases)

A coverage badge is intentionally not included yet: doing so honestly needs a
Codecov/Coveralls account and upload token, which isn't set up. Per-package
coverage is enforced in CI regardless (`make coverage`, see
`hack/check-coverage.sh`); a badge is a TODO, not a claim to fake in the
meantime.

A Kubernetes operator that continuously syncs LDAP/Active Directory group
membership into `RoleBinding`/`ClusterRoleBinding` objects, declaratively,
through three CRDs. It reconciles like any other controller-runtime
operator: drift introduced by hand (or by anything else) gets corrected on
the next sync, not just at apply time.

Inspired by the gap left by [rbacsync](https://github.com/cruise-automation/rbacsync)
(cruise-automation) - a similar idea, but GSuite-only, built on the
pre-controller-runtime client-gen/informer pattern, and unmaintained since
December 2023. LDAP/AD support was never added there.

This project handles **authorization sync only** - it does not authenticate
anyone. Pair it with [Dex](https://dexidp.io/), OIDC, or `kubelogin` for
that; this operator just keeps RBAC in sync with whatever groups your
directory says a user belongs to.

## Non-goals

- Authentication. That's Dex/Keycloak/OpenUnison's job.
- Running the LDAP/AD server itself.
- A UI. `kubectl` and Prometheus metrics are the interface.
- SCIM/GSuite/Okta as a source - the `Grouper` interface
  (`internal/ldapclient/grouper.go`) is written so a second provider could be
  added later without touching the reconcilers, but only LDAP/AD is
  implemented.

## How it works

| CRD | Scope | Manages |
|---|---|---|
| `LDAPProvider` | Cluster | Connection details for a directory; runs its own bind-only health check |
| `RBACGroupBinding` | Namespaced | One `RoleBinding` per CR, subjects synced from `spec.groupDN`'s members |
| `ClusterRBACGroupBinding` | Cluster | One `ClusterRoleBinding` per CR, same idea |

Every reconcile resolves `spec.groupDN`'s membership from the referenced
`LDAPProvider`, diffs it against the managed RoleBinding/ClusterRoleBinding's
current subjects, and creates/updates as needed. Members are matched as RBAC
`User` subjects, named by the directory attribute in
`LDAPProvider.spec.usernameAttribute` (default `uid`; use `sAMAccountName` or
`userPrincipalName` for Active Directory) - this needs to match whatever
your OIDC/Dex layer presents as the authenticated username claim, since RBAC
`User` subjects match by exact string.

If the directory is unreachable, or `spec.groupDN` doesn't currently resolve
to anything, the binding is marked `Degraded`/`GroupNotFound` but **the
managed RoleBinding is left untouched** - membership never gets wiped out by
an outage. `kubectl get rbacgroupbinding` surfaces provider, group, role,
member count, readiness and last sync time directly:

```
NAME             PROVIDER   GROUP                                     ROLE   MEMBERS   READY   LAST SYNC
data-team-edit   corp-ad    cn=data-team,ou=groups,dc=corp,dc=local   edit   3         True    12s
```

## Quickstart: kind + OpenLDAP

Requires `kind`, `helm`, `kubectl`, and Docker.

**1. Start OpenLDAP locally and seed some test data:**

```sh
docker compose up -d
make ldap-seed
```

This seeds `dc=corp,dc=local` with two users (`alice`, `bob`), a third
(`carol`), and two `groupOfNames` groups (`data-team`, `platform-admins`) -
see `test/utils/ldif/seed.ldif`.

**2. Create a kind cluster and give it a route to that OpenLDAP container:**

```sh
kind create cluster --name ldaprbac-dev
docker network connect directory-rbac-operator_default ldaprbac-dev-control-plane
LDAP_IP=$(docker inspect directory-rbac-operator-openldap \
  --format '{{ (index .NetworkSettings.Networks "directory-rbac-operator_default").IPAddress }}')
```

**3. Build the operator image and load it into kind:**

```sh
make docker-build
kind load docker-image directory-rbac-operator:dev --name ldaprbac-dev
```

**4. Install the chart:**

```sh
kubectl create namespace ldaprbac-system
kubectl create secret generic ldap-bind-credentials -n ldaprbac-system \
  --from-literal=password=admin
helm install ldaprbac charts/directory-rbac-operator -n ldaprbac-system \
  --set image.repository=directory-rbac-operator --set image.tag=dev
```

**5. Point it at the seeded directory and create a binding:**

```sh
kubectl create namespace data-platform
cat <<EOF | kubectl apply -f -
apiVersion: ldaprbac.io/v1alpha1
kind: LDAPProvider
metadata:
  name: corp-ad
spec:
  url: "ldap://${LDAP_IP}:389"
  bindDN: "cn=admin,dc=corp,dc=local"
  bindPasswordSecretRef:
    name: ldap-bind-credentials
    key: password
  insecureSkipTLS: true # dev-only OpenLDAP has no TLS; see Security below
  userSearchBase: "ou=people,dc=corp,dc=local"
  groupSearchBase: "ou=groups,dc=corp,dc=local"
  syncInterval: 30s
  usernameAttribute: uid
---
apiVersion: ldaprbac.io/v1alpha1
kind: RBACGroupBinding
metadata:
  name: data-team-edit
  namespace: data-platform
spec:
  providerRef: corp-ad
  groupDN: "cn=data-team,ou=groups,dc=corp,dc=local"
  roleRef:
    kind: ClusterRole
    name: edit
EOF
```

**6. Watch it converge:**

```sh
kubectl get rbacgroupbinding -n data-platform -w
kubectl get rolebinding data-team-edit -n data-platform -o yaml
```

The RoleBinding's subjects should show `alice` and `bob` (`data-team`'s
members). Add `carol` to the group and it picks her up on the next sync:

```sh
docker compose exec -T openldap ldapmodify -x -H ldap://localhost \
  -D "cn=admin,dc=corp,dc=local" -w admin <<EOF
dn: cn=data-team,ou=groups,dc=corp,dc=local
changetype: modify
add: member
member: uid=carol,ou=people,dc=corp,dc=local
EOF
```

Stop OpenLDAP (`docker compose stop openldap`) and the binding flips to
`Degraded` while the RoleBinding's subjects stay exactly as they were.

**Cleanup:**

```sh
kind delete cluster --name ldaprbac-dev
docker compose down -v
```

## Security

- Bind passwords and CA bundles are always read from a Secret, never
  accepted inline on the CR. `LDAPProvider` is cluster-scoped and so has no
  namespace of its own; every provider's Secrets are read from a single
  operator-wide namespace (`--secret-namespace`, defaults to the release
  namespace).
- LDAPS and StartTLS are both supported. Plaintext (`ldap://` with no
  StartTLS) requires `insecureSkipTLS: true` set explicitly - there is no
  silent plaintext fallback, and setting it logs a warning. Conversely,
  `ldap://` with neither `insecureSkipTLS` nor `tlsConfig.caSecretRef` set is
  rejected outright (`Ready=False`, reason `InvalidSpec`): letting that
  silently negotiate StartTLS against the system trust store is an easy way
  to end up trusting nothing in particular against an internal CA.
- `rbac.strict` (Helm value, default `false`) moves Secret access from a
  cluster-wide rule into a namespaced `Role` scoped to wherever
  `--secret-namespace` actually points, so a compromised operator pod can't
  read Secrets outside that one namespace.
- **The operator's ServiceAccount needs `bind` on `roles`/`clusterroles`.**
  Kubernetes refuses to create a RoleBinding/ClusterRoleBinding that grants
  permissions the requester doesn't already hold, unless the requester also
  has `bind` on the referenced role - there's no way to scope that down to
  "only the roles some future `RBACGroupBinding` will reference," since
  those names aren't known ahead of time. This is inherent to how any
  group-to-RBAC sync tool has to work, not something specific to this
  operator, but it's worth being aware of before granting the chart's
  ClusterRole in a security-sensitive cluster.

## Observability

- Metrics on the existing `/metrics` endpoint: `ldaprbac_sync_total` (by kind
  and result), `ldaprbac_sync_duration_seconds`, `ldaprbac_ldap_errors_total`
  (by provider), `ldaprbac_members_count` (by kind/namespace/name). The chart
  can expose these via an optional `ServiceMonitor`
  (`metrics.serviceMonitor.enabled`).
- Kubernetes Events on every meaningful reconcile outcome - RoleBinding/
  ClusterRoleBinding created/updated/recreated, sync failures, group-not-found,
  invalid provider specs, blocked provider deletions - so `kubectl describe`
  gives the same audit trail a security team would otherwise reconstruct from
  logs.
- LDAP requests are rate-limited per provider (shared across its health check
  and every binding that references it), so a burst of reconciles - many
  bindings against one directory, a rapid restart loop - can't hammer a
  shared AD Global Catalog.

## Releases

Pushing a `vX.Y.Z` tag publishes a `linux/amd64` and `linux/arm64` image to
GitHub Container Registry, packages the matching Helm chart to the GitHub OCI
registry, and creates a GitHub Release with generated notes. Image signing
with Cosign is intentionally not enabled yet; add keyless signing before
using release artifacts in a supply-chain-enforced environment.

## Development

```sh
make generate manifests  # regenerate deepcopy + CRD/RBAC YAML from markers
make test                # unit tests + envtest (spins up a real API server)
make helm-lint            # lint the chart (also syncs charts/.../crds/)
./test/e2e/run.sh         # real kind + docker-compose OpenLDAP smoke test
                          # (needs the cluster/image steps from the
                          # quickstart above done first; see .github/
                          # workflows/e2e.yaml for the full sequence)
```

No `kubebuilder` CLI is required - `controller-gen`, `setup-envtest`, and
friends are fetched on demand via `go run` and pinned by version in the
Makefile. CI (`.github/workflows/ci.yaml`) runs build/vet/fmt/generated-diff/
unit+envtest and a Helm chart lint on every push and PR; `e2e.yaml` runs the
same kind+OpenLDAP flow as the quickstart, including the outage and
garbage-collection checks below.
