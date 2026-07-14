# Installation

Install the chart after creating a Secret containing the provider bind
password in the operator's secret namespace:

```sh
helm install ldaprbac oci://ghcr.io/d3dov/charts/directory-rbac-operator \
  --namespace ldaprbac-system --create-namespace
```

For a local checkout, replace the OCI reference with
`charts/directory-rbac-operator`.

## Values reference

| Value | Default | Purpose |
|---|---:|---|
| `image.repository`, `image.tag` | GHCR repository, chart app version | Operator image |
| `replicaCount` | `1` | Number of manager pods |
| `leaderElection.enabled` | `false` | Required for safe active/passive replicas |
| `secretNamespace` | release namespace | Namespace containing every provider Secret |
| `rbac.strict` | `false` | Restrict Secret reads to the secret namespace |
| `metrics.bindAddress` | `:8080` | Metrics listener |
| `healthProbe.bindAddress` | `:8081` | Health and readiness listener |
| `logLevel` | `info` | Controller-runtime Zap level |
| `resources` | 50m/64Mi request, 200m/128Mi limit | Pod capacity defaults |
| `podDisruptionBudget.enabled` | `true` | Keep `minAvailable` pods during voluntary disruption |
| `podSecurityContext` / `securityContext` | non-root, RuntimeDefault, read-only | Restricted pod defaults |
| `metrics.serviceMonitor.enabled` | `false` | Create a Prometheus Operator ServiceMonitor |

For replicas above one, enable leader election and review PDB `minAvailable`
for the desired maintenance availability budget.
