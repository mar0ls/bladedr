# The control plane ships architecture-specific probe and sensor binaries to Linux
# targets over SSH. Policies remain an operator-mounted, independently versioned
# bundle at /etc/bladedr/policies.
# Base images are pinned by digest, matching the SHA-pinned GitHub Actions in
# .github/workflows/ci.yml: a floating tag lets the contents of a "reproducible"
# build change under you, which is the entry point for a supply-chain substitution.
# Refresh both digests deliberately, in their own commit.
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/bladedr-server ./cmd/bladedr-server && \
    CGO_ENABLED=0 go build -o /out/bladectl ./cmd/bladectl && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/bladedr-probe.linux-amd64 ./cmd/bladedr-probe && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /out/bladedr-probe.linux-arm64 ./cmd/bladedr-probe && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/bladedr-sensor.linux-amd64 ./cmd/bladedr-sensor && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /out/bladedr-sensor.linux-arm64 ./cmd/bladedr-sensor

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN adduser -D -u 10001 bladedr && mkdir -p /etc/bladedr/policies && chown -R bladedr:bladedr /etc/bladedr
COPY --from=build /out/ /usr/local/bin/
USER bladedr
ENV BLADEDR_ADDR=:8080 \
    BLADEDR_PROBE_LINUX_AMD64=/usr/local/bin/bladedr-probe.linux-amd64 \
    BLADEDR_PROBE_LINUX_ARM64=/usr/local/bin/bladedr-probe.linux-arm64 \
    BLADEDR_SENSOR_LINUX_AMD64=/usr/local/bin/bladedr-sensor.linux-amd64 \
    BLADEDR_SENSOR_LINUX_ARM64=/usr/local/bin/bladedr-sensor.linux-arm64 \
    BLADEDR_POLICY_DIR=/etc/bladedr/policies
EXPOSE 8080
# /readyz also verifies the store is reachable, so an orchestrator stops routing to
# a container that is up but has lost its database. wget is in alpine's busybox.
# The probe assumes the image defaults above (plaintext on :8080); override it when
# running with BLADEDR_TLS_CERT or a different BLADEDR_ADDR.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/readyz || exit 1
ENTRYPOINT ["/usr/local/bin/bladedr-server"]
