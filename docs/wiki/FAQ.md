# FAQ

## Why are managed RBAC subjects `User`, not `Group`?

Kubernetes RBAC can bind a `Group`, but LDAP group names are not automatically
Kubernetes authentication groups. The authentication layer (OIDC, webhook, or
client certificates) decides which user and group claims Kubernetes sees.
Projecting resolved directory members as `User` subjects makes the sync result
independent of undocumented claim-to-group translation and gives deterministic
membership even when the identity provider emits no group claim. Set
`usernameAttribute` to the exact username claim value.

## Does an LDAP outage remove access?

No. The binding becomes `Degraded`, while its last successfully applied
subjects remain unchanged.

## Does the operator authenticate users?

No. It only maintains Kubernetes authorization objects.

## Can I run multiple replicas?

Yes. Enable `leaderElection.enabled` before doing so.
