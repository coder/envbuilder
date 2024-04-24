GOARCH := $(shell go env GOARCH)
PWD=$(shell pwd)

develop:
	./scripts/develop.sh

build: scripts/envbuilder-$(GOARCH)
	./scripts/build.sh

.PHONY: test
test: test-registry test-images
	go test -count=1 ./...

# Starts a local Docker registry on port 5000 with a local disk cache.
.PHONY: test-registry
test-registry: .registry-cache
	if [ ! curl -fsSL http://localhost:5000/v2/_catalog >/dev/null 2>&1 ]; then \
		docker rm -f envbuilder-registry; \
		docker run -d -p 5000:5000 --name envbuilder-registry --volume $(PWD)/.registry-cache:/var/lib/registry registry:2; \
	fi

# Pulls images referenced in integration tests and pushes them to the local cache.
.PHONY: test-images
test-images: .registry-cache .registry-cache/docker/registry/v2/repositories/envbuilder-test-alpine .registry-cache/docker/registry/v2/repositories/envbuilder-test-ubuntu

.registry-cache:
	mkdir -p .registry-cache && chmod -R ag+w .registry-cache

.registry-cache/docker/registry/v2/repositories/envbuilder-test-alpine:
	docker pull alpine:latest
	docker tag alpine:latest localhost:5000/envbuilder-test-alpine:latest
	docker push localhost:5000/envbuilder-test-alpine:latest

.registry-cache/docker/registry/v2/repositories/envbuilder-test-ubuntu:
	docker pull ubuntu:latest
	docker tag ubuntu:latest localhost:5000/envbuilder-test-ubuntu:latest
	docker push localhost:5000/envbuilder-test-ubuntu:latest