# syntax=docker/dockerfile:1.7

FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY . .

# All Go dependencies are vendored. Keeping this build step networkless makes
# the dependency boundary explicit after the pinned builder image is cached.
RUN --network=none CGO_ENABLED=0 GOFLAGS=-mod=vendor go build \
    -trimpath -buildvcs=false -ldflags="-s -w" \
    -o /out/cairn ./cmd/cairn

FROM scratch

COPY --from=builder /out/cairn /cairn
USER 65532:65532
ENTRYPOINT ["/cairn"]
