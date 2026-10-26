# syntax=docker/dockerfile:1
# manar-edge-gateway: static binary on distroless static, non-root. The binary carries the
# cap_net_admin file capability so uid 65532 can configure wg0 and nftables when the pod grants
# NET_ADMIN (Kubernetes has no ambient capabilities; the pod needs allowPrivilegeEscalation: true
# for the file capability to apply, see charts/manar-edge-gateway).
# Newer patch than the go.mod floor: go1.26.10 carries the net/http and crypto/x509 fixes.
FROM golang:1.26.10@sha256:672c944cfd07599b5f1bb179869270cdc94c6254e41db4d431259693cb286b82 AS build
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/manar-edge-gateway ./cmd/manar-edge-gateway \
    && setcap cap_net_admin+ep /out/manar-edge-gateway

# gcr.io/distroless/static-debian13:nonroot, resolved 2026-10-25.
FROM gcr.io/distroless/static-debian13@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/manar-edge-gateway /usr/local/bin/manar-edge-gateway
USER 65532:65532
EXPOSE 51820/udp 9090/tcp
ENTRYPOINT ["/usr/local/bin/manar-edge-gateway"]
