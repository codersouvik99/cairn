# syntax=docker/dockerfile:1.7

FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY . .

# All Go dependencies are vendored. The documented docker build command uses
# --network=none, so this build step cannot fetch anything after the pinned
# builder image is cached. Avoid Dockerfile-only BuildKit syntax so the image
# also builds with the standard Docker legacy builder.
RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor go build \
    -trimpath -buildvcs=false -ldflags="-s -w" \
    -o /out/cairn ./cmd/cairn

FROM scratch

COPY --from=builder /out/cairn /cairn
USER 65532:65532
ENTRYPOINT ["/cairn"]
