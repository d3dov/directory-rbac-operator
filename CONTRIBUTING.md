# Contributing

Thanks for considering a contribution. This project is a Kubernetes operator
built on `controller-runtime`; see the README for what it does and why.

## Development setup

Requires Go (version pinned in `go.mod`), Docker, `kind`, and `helm`. No
`kubebuilder` CLI is needed - `controller-gen`, `setup-envtest`, and friends
are fetched on demand via `go run`, pinned by version in the `Makefile`.

```sh
go build ./...
make test          # unit tests + envtest (spins up a real API server)
make manifests      # regenerate CRD/RBAC YAML after changing API types or +kubebuilder:rbac markers
make generate       # regenerate deepcopy methods after changing API types
make helm-lint      # lint the chart, syncing charts/.../crds/ first
```

For a full local run against a real directory (kind + docker-compose
OpenLDAP), see the [Quickstart](README.md#quickstart-kind--openldap) in the
README, or run `./test/e2e/run.sh` directly against a cluster you've already
set up per that quickstart.

## Before opening a PR

- `go build ./...`, `go vet ./...`, and `gofmt -l .` (empty output) must all
  be clean.
- `make test` must pass.
- If you changed API types (`api/v1alpha1/`) or `+kubebuilder:rbac` markers,
  run `make generate manifests helm-crds` and commit the resulting diff -
  CI checks that generated files aren't stale.
- Add tests for new logic in the package it lives in; `internal/controller`,
  `internal/ldapclient`, and `internal/rbacsync` are expected to stay
  thoroughly covered.

## Commit style

Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`). Keep commits
focused - one logical change per commit - and write the message around *why*,
not a restatement of the diff.

## Pull requests

- Keep PRs scoped to one change; split unrelated fixes into separate PRs.
- Describe the motivation and, for behavioral changes, how you verified it
  (test output, or a manual repro against a real/kind directory).
- Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes.

## Reporting bugs and requesting features

Use the issue templates. For security issues, see
[SECURITY.md](SECURITY.md) instead of a public issue.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
