# Build stage — Red Hat Hardened Images Go toolchain embeds the validated
# FIPS module in all binaries automatically.
FROM registry.access.redhat.com/hi/go:1.27-fips AS builder

WORKDIR /src

# Version metadata stamped into the binary via ldflags.
ARG VERSION=0.0.0+dev
ARG COMMIT=unknown

# Download modules first so the layer is cached when only source changes.
COPY go.mod go.sum ./
RUN go mod download

# Build the static binary. CGO_ENABLED=0 matches .goreleaser.yaml so the
# runtime stage needs no C libraries.
COPY . .
RUN CGO_ENABLED=0 go build \
        -trimpath \
        -ldflags "-s -w \
            -X github.com/crowdstrike/chronicle-intel-bridge/internal/version.Version=${VERSION} \
            -X github.com/crowdstrike/chronicle-intel-bridge/internal/version.Commit=${COMMIT}" \
        -o /tmp/ccib \
        ./cmd/ccib

# Runtime stage — minimal hardened base; GODEBUG runs the binary in FIPS mode.
FROM registry.access.redhat.com/hi/core-runtime:latest

# The binary lives on PATH, separate from the working directory so it never
# collides with the config/ and data/ trees.
COPY --from=builder /tmp/ccib /usr/local/bin/ccib

# Run from /ccib so the default relative state path (data/state.json) resolves
# into the data volume declared below.
WORKDIR /ccib

# data/ holds the resume marker; expose it as a volume so state survives
# restarts. The build runs as the base image's non-root user (UID 65532, primary
# group 0), so mkdir already creates data/ owned by 65532:0 — no chown needed.
# Make it group-writable so it works whether the default UID 65532 or an
# arbitrary OpenShift UID (always in group 0) runs.
RUN mkdir -p /ccib/data && chmod -R g=u /ccib/data
VOLUME /ccib/data

# FIPS mode is off by default (GODEBUG empty). The validated FIPS module is
# compiled into the binary regardless, so enabling it is a pure runtime toggle:
# docker run -e GODEBUG=fips140=on ... (values: on, only).
ENV GODEBUG=

# No USER line: the hardened base image already defaults to its built-in
# non-root user (UID 65532, group 0), which image scanners and Kubernetes
# runAsNonRoot honor. Inheriting it avoids hardcoding a UID and tracks the base
# image if that default ever changes.
ENTRYPOINT ["/usr/local/bin/ccib"]
