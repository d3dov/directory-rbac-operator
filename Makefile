SHELL := /usr/bin/env bash -o pipefail
.SHELLFLAGS := -ec

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

CONTROLLER_TOOLS_VERSION ?= v0.21.0
ENVTEST_VERSION ?= v0.24.1
ENVTEST_K8S_VERSION ?= 1.33.0

.PHONY: envtest
envtest: $(LOCALBIN) ## Ensure the envtest binaries (etcd, kube-apiserver, kubectl) are present.
	go run sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path

.PHONY: all
all: build

.PHONY: generate
generate: ## Generate DeepCopy/DeepCopyInto/DeepCopyObject methods for API types.
	go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION) \
		object:headerFile=hack/boilerplate.go.txt paths=./api/...

.PHONY: manifests
manifests: ## Generate CRD, RBAC and webhook manifests from kubebuilder markers.
	go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION) \
		crd rbac:roleName=manager-role webhook paths=./... \
		output:crd:artifacts:config=config/crd/bases \
		output:rbac:artifacts:config=config/rbac \
		output:webhook:artifacts:config=config/webhook

.PHONY: build
build: fmt vet
	go build -o bin/manager main.go

.PHONY: run
run: fmt vet
	go run ./main.go

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: test
test: fmt vet envtest
	KUBEBUILDER_ASSETS="$$(go run sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" \
		go test ./... -count=1
