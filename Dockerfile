# bladedr-server runs on any platform; this image bundles the Linux probe binaries
# it ships to scan targets over SSH. Scanning itself is always Linux-only.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/bladedr-server ./cmd/bladedr-server && \
    CGO_ENABLED=0 GOARCH=amd64 go build -o /out/bladedr-probe.linux-amd64 ./cmd/bladedr-probe && \
    CGO_ENABLED=0 GOARCH=arm64 go build -o /out/bladedr-probe.linux-arm64 ./cmd/bladedr-probe

FROM alpine:3.20
RUN adduser -D -u 10001 bladedr
COPY --from=build /out/ /usr/local/bin/
USER bladedr
ENV BLADEDR_ADDR=:8080 \
    BLADEDR_PROBE_LINUX_AMD64=/usr/local/bin/bladedr-probe.linux-amd64 \
    BLADEDR_PROBE_LINUX_ARM64=/usr/local/bin/bladedr-probe.linux-arm64
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/bladedr-server"]
