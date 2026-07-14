# Directory backends

Set `LDAPProvider.spec.directoryType` explicitly. Valid values are
`OpenLDAP` (default), `ActiveDirectory`, and `FreeIPA`; unsupported values are
rejected by CRD validation.

| Backend | Membership query | Paging | Nested groups |
|---|---|---|---|
| OpenLDAP | Plain `memberOf=<group DN>` reverse search, then `member` fallback | No special branch | Depends on the configured memberOf overlay |
| ActiveDirectory | Reverse search | RFC 2696 paged results | `LDAP_MATCHING_RULE_IN_CHAIN` |
| FreeIPA | Plain `memberOf=<group DN>` reverse search | No special branch | Computed by 389 Directory Server's MemberOf plugin |

## Active Directory

AD commonly returns at most 1,000 entries for an unpaged query. The client
uses the RFC 2696 paged-results control for the reverse membership search when
`directoryType: ActiveDirectory` is set. It intentionally does **not** chase
LDAP referrals: credentials, trust boundaries, TLS policy, and loop limits
must be an explicit future configuration decision. Referral responses are
logged and returned as errors instead of silently producing partial RBAC.

For nested groups, AD evaluates the server-side extensible matching rule
`1.2.840.113556.1.4.1941` (`LDAP_MATCHING_RULE_IN_CHAIN`) on `memberOf`.
Use `sAMAccountName` or `userPrincipalName` for `usernameAttribute` when that
matches the Kubernetes authentication claim.

## OpenLDAP and FreeIPA

OpenLDAP's memberOf overlay is optional, so direct reverse lookup may return
no entries and the client falls back to the group's `member` attribute.
FreeIPA uses 389 Directory Server. Its MemberOf plugin maintains the recursive
membership view, so FreeIPA deliberately uses the normal equality filter and
does not send AD's matching-rule OID; a separate recursive client algorithm
would be redundant and less reliable.
