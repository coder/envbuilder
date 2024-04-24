GOARCH := $(shell go env GOARCH)

develop:
	./scripts/develop.sh

build: scripts/envbuilder-$(GOARCH)
	./scripts/build.sh

.PHONY: test
test: test-registry test-images
	go test -count=1 ./...

# Starts a local Docker registry on port 5000 with a local disk cache.
test-registry:
	curl -fsSL http://localhost:5000/v2/_catalog || \
	docker run -d -p 5000:5000 --name envbuilder-registry --volume $(pwd)/.registry-cache:/var/lib/registry registry:2

# 
test-images: .registry-cache .registry-cache/docker/registry/v2/repositories/envbuilder-test-alpine .registry-cache/docker/registry/v2/repositories/envbuilder-test-ubuntu

.registry-cache:
	mkdir -p .registry-cache

.registry-cache/docker/registry/v2/repositories/envbuilder-test-alpine:
	docker pull alpine:latest
	docker tag alpine:latest localhost:5000/envbuilder-test-alpine:latest
	docker push localhost:5000/envbuilder-test-alpine:latest

.registry-cache/docker/registry/v2/repositories/envbuilder-test-ubuntu:
	docker pull ubuntu:latest
	docker tag ubuntu:latest localhost:5000/envbuilder-test-ubuntu:latest
	docker push localhost:5000/envbuilder-test-ubuntu:latest