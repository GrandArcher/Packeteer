# syntax=docker/dockerfile:1

# ---- build stage: cross-compiles for the target platform without QEMU ----
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/packeteer ./cmd/controller

# ---- runtime stage ----
# Alpine (not distroless) so exec plugins written as shell scripts work in the
# stock image. The image ships only the documentation-prefix example config.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
 && mkdir -p /etc/packeteer/plugins
COPY --from=build /out/packeteer /usr/local/bin/packeteer
COPY config.example.yaml /etc/packeteer/config.example.yaml

# Runs as root inside the container: raw ICMP sockets and BGP port 179 need
# CAP_NET_RAW / CAP_NET_BIND_SERVICE. Docker grants only the capabilities you
# pass with --cap-add (plus its defaults); see README "Security notes".
ENV PACKETEER_CONFIG=/etc/packeteer/config.yaml

# Ops surface (dashboard, /metrics, /api). The process binds http.listen
# from the mounted config, which defaults to 127.0.0.1:8080. With
# --network host that is the host loopback; this EXPOSE documents the port.
EXPOSE 8080

LABEL org.opencontainers.image.source="https://github.com/GrandArcher/Packeteer" \
      org.opencontainers.image.description="Packeteer: BGP path performance controller (observe-first)" \
      org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["/usr/local/bin/packeteer"]
