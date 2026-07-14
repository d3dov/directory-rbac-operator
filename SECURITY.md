# Security Policy

## Supported Versions

This project is pre-1.0 (see [CHANGELOG.md](CHANGELOG.md)). Until a `v1.0.0`
release, only the `main` branch / latest tagged release receives security
fixes.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report it privately using one of:

- [GitHub Security Advisories](https://github.com/denis-da-engineer/directory-rbac-operator/security/advisories/new)
  for this repository (preferred - keeps the report and discussion private
  until a fix ships).
- Email gibsartines@gmail.com with a description of the issue and, if
  possible, steps to reproduce it.

Please include:

- The affected version/commit.
- The operator's deployment context if relevant (e.g. `rbac.strict` setting,
  `insecureSkipTLS` usage) - this project's threat model is described in the
  README's [Security](README.md#security) section.
- Impact and a proof of concept, if you have one.

We aim to acknowledge reports within 5 business days and to agree on a
disclosure timeline with the reporter before any public write-up.

## Scope

In scope: the operator's controllers, `internal/ldapclient`, the Helm chart's
RBAC/Pod security posture, and the CRD API surface.

Out of scope: vulnerabilities in upstream dependencies (please report those
upstream first; we'll track and update once a fix is available) and issues
requiring the operator's own bind credentials to already be compromised.
