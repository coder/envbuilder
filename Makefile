GOARCH := $(shell go env GOARCH)
PWD=$(shell pwd)

GO_SRC_FILES := $(shell find . -type f -name '*.go' -not -name '*_test.go')
GO_TEST_FILES := $(shell find . -type f -not -name '*.go' -name '*_test.go')
GOLDEN_FILES := $(shell find . -type f -name '*.golden')
SHELL_SRC_FILES := $(shell find . -type f -name '*.sh')
GOLANGCI_LINT_VERSION := v1.59.1

fmt: $(shell find . -type f -name '*.go')
	go run mvdan.cc/gofumpt@v0.6.0 -l -w .

.PHONY: lint
lint: lint/go lint/shellcheck

.PHONY: lint/go
lint/go: $(GO_SRC_FILES)
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	golangci-lint run --timeout=10m

.PHONY: lint/shellcheck
lint/shellcheck: $(SHELL_SRC_FILES)
	echo "--- shellcheck"
	shellcheck --external-sources $(SHELL_SRC_FILES)

develop:
	./scripts/develop.sh

build: scripts/envbuilder-$(GOARCH)
	./scripts/build.sh

.PHONY: update-golden-files
update-golden-files: .gen-golden

.gen-golden: $(GOLDEN_FILES) $(GO_SRC_FILES) $(GO_TEST_FILES)
	go test ./options -update
	@touch "$@"

docs: options/options.go options/options_test.go
	go run ./scripts/docsgen/main.go

.PHONY: test
test: test-registry
	go test -count=1 ./...

test-race:
	go test -race -count=3 ./...

.PHONY: update-kaniko-fork
update-kaniko-fork:
	go mod edit -replace github.com/GoogleContainerTools/kaniko=github.com/coder/kaniko@main
	go mod tidy

# Starts a local Docker registry on port 5000 with a local disk cache.
.PHONY: test-registry
test-registry: test-registry-container test-images-pull test-images-push

.PHONY: test-registry-container
test-registry-container: .registry-cache
	if ! curl -fsSL http://localhost:5000/v2/_catalog > /dev/null 2>&1; then \
		docker rm -f envbuilder-registry && \
		docker run -d -p 5000:5000 --name envbuilder-registry --volume $(PWD)/.registry-cache:/var/lib/registry registry:2; \
	fi

# Pulls images referenced in integration tests and pushes them to the local cache.
.PHONY: test-images-push
test-images-push: .registry-cache/docker/registry/v2/repositories/envbuilder-test-alpine .registry-cache/docker/registry/v2/repositories/envbuilder-test-ubuntu .registry-cache/docker/registry/v2/repositories/envbuilder-test-codercom-code-server

.PHONY: test-images-pull
test-images-pull:
	docker pull alpine:latest
	docker tag alpine:latest localhost:5000/envbuilder-test-alpine:latest
	docker pull ubuntu:latest
	docker tag ubuntu:latest localhost:5000/envbuilder-test-ubuntu:latest
	docker pull codercom/code-server:latest
	docker tag codercom/code-server:latest localhost:5000/envbuilder-test-codercom-code-server:latest

.registry-cache:
	mkdir -p .registry-cache && chmod -R ag+w .registry-cache

.registry-cache/docker/registry/v2/repositories/envbuilder-test-alpine:
	docker push localhost:5000/envbuilder-test-alpine:latest

.registry-cache/docker/registry/v2/repositories/envbuilder-test-ubuntu:
	docker push localhost:5000/envbuilder-test-ubuntu:latest

.registry-cache/docker/registry/v2/repositories/envbuilder-test-codercom-code-server:
	docker push localhost:5000/envbuilder-test-codercom-code-server:latest