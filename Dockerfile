# syntax=docker/dockerfile:1

# The newest Go release; see the release workflow for why.
ARG GO_VERSION=1.27

FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w \
        -X github.com/Voskan/codexsentinel/internal/version.Version=${VERSION} \
        -X github.com/Voskan/codexsentinel/internal/version.Commit=${COMMIT} \
        -X github.com/Voskan/codexsentinel/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/codex-cli ./cmd/codex-cli

# The runtime image keeps the Go toolchain and git: the scanner loads the
# analyzed module with "go list" and reads "git diff" in --diff mode.
FROM golang:${GO_VERSION}-alpine
RUN apk add --no-cache ca-certificates git \
    && git config --system --add safe.directory '*' \
    && addgroup -S nonroot \
    && adduser -S -D -G nonroot -h /home/nonroot nonroot
COPY --from=builder /out/codex-cli /usr/local/bin/codex-cli
ENV HOME=/home/nonroot \
    GOPATH=/home/nonroot/go \
    GOCACHE=/home/nonroot/.cache/go-build \
    GOTOOLCHAIN=auto
USER nonroot
WORKDIR /workspace
ENTRYPOINT ["codex-cli"]
CMD ["scan", "."]
