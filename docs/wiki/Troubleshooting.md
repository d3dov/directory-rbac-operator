# Troubleshooting

Start with CR conditions and Events:

```sh
kubectl get ldapprovider,rbacgroupbinding,clusterrbacgroupbinding -A
kubectl describe ldapprovider <name>
kubectl describe rbacgroupbinding -n <namespace> <name>
kubectl -n <operator-namespace> logs deploy/<release-name> --tail=200
```

| Symptom | Likely cause and action |
|---|---|
| `InvalidSpec` | For `ldap://`, configure StartTLS CA or explicitly opt into `insecureSkipTLS`. |
| `BindFailed` / `Degraded` | Check DNS, network policy, bind DN/password Secret, and directory TLS certificate. Existing subjects intentionally remain. |
| Empty membership | Verify group DN, search bases, `memberOf`/`member` schema, and `usernameAttribute`. |
| AD members stop near 1,000 | Confirm `directoryType: ActiveDirectory`; this enables paged search. |
| Nested AD groups missing | Confirm the service account can search and that the backend is AD, not FreeIPA/OpenLDAP. |
| Pod unready | Check cached LDAPProvider conditions; `/readyz` does not make live LDAP calls. |

For a local reproduction, use the README's kind + OpenLDAP quickstart and
compare the generated `RoleBinding` subjects with the LDAP entries.
