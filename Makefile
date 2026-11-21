VERSION ?= $(shell (git describe --tags --exact-match 2>/dev/null || echo v0.3.0-dev) | sed 's/^v//')
ifeq ($(strip $(VERSION)),)
override VERSION := 0.3.0-dev
endif
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

MODULE  := github.com/yogenpoonudurai/enki
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build build-cli build-mcp build-cloud test vet fmt cross clean install

build: build-cli build-mcp build-cloud

build-cli:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/enki ./cmd/enki

build-mcp:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/enki-mcp ./cmd/enki-mcp

build-cloud:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/enki-cloud ./cmd/enki-cloud

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/enki ./cmd/enki-mcp ./cmd/enki-cloud

test:
	go test ./...

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
	@set -e; for arch in amd64 arm64; do \
		echo "building linux/$$arch (enki-cloud)"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath \
			-ldflags "$(LDFLAGS)" -o bin/enki-cloud-linux-$$arch ./cmd/enki-cloud; \
	done

clean:
	rm -rf bin dist
