// Package version holds build-time metadata injected via -ldflags.
package version

// Version is overridden at build time, e.g.:
//
//	go build -ldflags "-X github.com/denis-da-engineer/directory-rbac-operator/internal/version.Version=$(git describe --tags --always)"
var Version = "dev"
