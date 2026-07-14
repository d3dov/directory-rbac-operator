## What and why

<!-- What does this change, and what problem does it solve? -->

## How was this verified?

<!--
Test output, a manual repro against a real/kind directory, etc.
"Added tests" is fine if the tests speak for themselves.
-->

## Checklist

- [ ] `go build ./...`, `go vet ./...`, `gofmt -l .` are clean
- [ ] `make test` passes
- [ ] `make generate manifests helm-crds` re-run and committed, if API types
      or `+kubebuilder:rbac` markers changed
- [ ] `CHANGELOG.md` updated under `[Unreleased]`, for user-visible changes
