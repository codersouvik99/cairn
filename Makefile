GO ?= ./.tools/go/bin/go
GOFLAGS ?= -mod=vendor

.PHONY: test build fmt vet

test:
	GOTOOLCHAIN=local GOFLAGS=$(GOFLAGS) $(GO) test ./...

build:
	mkdir -p bin
	GOTOOLCHAIN=local GOFLAGS=$(GOFLAGS) CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -o bin/cairn ./cmd/cairn

fmt:
	GOTOOLCHAIN=local $(GO) fmt ./...

vet:
	GOTOOLCHAIN=local GOFLAGS=$(GOFLAGS) $(GO) vet ./...
