# CRD reference

## LDAPProvider (cluster scoped)

Required fields are `url`, `bindDN`, `bindPasswordSecretRef`,
`userSearchBase`, `groupSearchBase`, and `syncInterval`. The Secret is always
looked up in `--secret-namespace`, never in an inline field.

`usernameAttribute` defaults to `uid`. `directoryType` defaults to `OpenLDAP`.
For `ldap://`, set either `insecureSkipTLS: true` for deliberately plaintext
development traffic or `tlsConfig.caSecretRef` to require StartTLS with a
private CA. Use `ldaps://` for implicit TLS.

Status includes `Ready`, `Degraded`, `ObservedGeneration`, and
`LastVerifiedTime`.

## RBACGroupBinding (namespaced)

Set `providerRef`, `groupDN`, and `roleRef` (`Role` or `ClusterRole`). The
operator creates a same-named `RoleBinding` in the CR's namespace.

## ClusterRBACGroupBinding (cluster scoped)

Set the same fields as `RBACGroupBinding`; the operator creates a same-named
`ClusterRoleBinding`. Use it only for roles intended to apply cluster-wide.
