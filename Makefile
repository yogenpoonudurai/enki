VERSION ?= $(shell (git describe --tags --exact-match 2>/dev/null || echo v0.4.0-dev) | sed 's/^v//')
ifeq ($(strip $(VERSION)),)
override VERSION := 0.4.0-dev
endif
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

MODULE  := github.com/yogenpoonudurai/enki
CONTAINER ?= $(shell command -v docker 2>/dev/null || command -v podman 2>/dev/null)
CONTAINER_KIND := $(notdir $(CONTAINER))
IMAGE ?= enki-dev
LOCAL_AI_NETWORK ?= host
LOCAL_AI_BASE_URL ?= http://127.0.0.1:11434/v1
LOCAL_AI_MODEL ?= qwen2.5:1.5b

ifneq ($(CONTAINER),)
CONTAINER_RUN = $(CONTAINER) run --rm
ifeq ($(CONTAINER_KIND),podman)
CONTAINER_RUN += --userns=keep-id
endif
endif
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build build-cli build-mcp build-cloud test vet fmt cross clean install \
	bench-detect bench-update \
	container-image test-container smoke-container smoke-local-container verify-docs-container shell-container

container-image:
	$(CONTAINER) build -f .devcontainer/Dockerfile -t $(IMAGE) .

# Run the unit suite inside a container; no host test execution.
test-container: container-image
	$(CONTAINER_RUN) -v "$(CURDIR)":/workspace -w /workspace $(IMAGE) make test

# End-to-end BYOK test against a local fake provider. The binary is compiled
# inside the container so the run never reuses host-built artifacts.
smoke-container: container-image
	$(CONTAINER_RUN) -v "$(CURDIR)":/workspace -w /workspace $(IMAGE) \
		sh -c 'go build -o /tmp/enki ./cmd/enki && ENKI_BIN=/tmp/enki ./demo/byok-smoke.sh'

shell-container: container-image
	$(CONTAINER_RUN) -it -v "$(CURDIR)":/workspace -w /workspace $(IMAGE) bash

# Triage against a local OpenAI-compatible server (Ollama by default), no key.
# Docker Desktop: LOCAL_AI_NETWORK=bridge and a host.docker.internal base URL.
smoke-local-container: container-image
	$(CONTAINER_RUN) --network=$(LOCAL_AI_NETWORK) \
		-e ENKI_AI_BASE_URL=$(LOCAL_AI_BASE_URL) -e ENKI_AI_MODEL=$(LOCAL_AI_MODEL) \
		-v "$(CURDIR)":/workspace -w /workspace $(IMAGE) \
		sh -c 'go build -o /tmp/enki ./cmd/enki && ENKI_BIN=/tmp/enki ./demo/local-smoke.sh'

# Execute every CLI command documented in README.md / docs/quickstart.md.
verify-docs-container: container-image
	$(CONTAINER_RUN) -v "$(CURDIR)":/workspace -w /workspace $(IMAGE) \
		sh -c 'go build -o /tmp/enki ./cmd/enki && ENKI_BIN=/tmp/enki ./demo/verify-docs.sh'

build: build-cli build-mcp

build-cli:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/enki ./cmd/enki

build-mcp:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/enki-mcp ./cmd/enki-mcp

build-cloud:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/enki-cloud ./cmd/enki-cloud

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/enki ./cmd/enki-mcp

test:
	go test ./...

bench-detect:
	go test ./internal/bench -run TestDetectionBenchmark -count=1 -v

bench-update:
	go test ./internal/bench -run TestDetectionBenchmark -count=1 -update -v

vet:
	go vet ./...

fmt:
	gofmt -w .

cross:
	@set -e; for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
			echo "building $$os/$$arch"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
				-ldflags "$(LDFLAGS)" -o bin/enki-$$os-$$arch$$ext ./cmd/enki; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
				-ldflags "$(LDFLAGS)" -o bin/enki-mcp-$$os-$$arch$$ext ./cmd/enki-mcp; \
		done; \
	done


clean:
	rm -rf bin dist
