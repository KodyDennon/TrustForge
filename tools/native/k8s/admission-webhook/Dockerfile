# SPDX-License-Identifier: Apache-2.0
# Multi-stage build for the TrustForge admission webhook.
# Final image is alpine-based and aims for ~10 MB.

# ---------- builder ----------
FROM golang:1.22-alpine AS builder
WORKDIR /src

# Cache deps
COPY go.mod go.sum* ./
RUN go mod download

COPY cmd/ ./cmd/

# Static, stripped, no debug symbols.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath \
    -ldflags="-s -w" \
    -o /out/tf-admission-webhook \
    ./cmd

# ---------- runtime ----------
FROM alpine:3.20
RUN addgroup -S tf && adduser -S tf -G tf \
 && apk add --no-cache ca-certificates

COPY --from=builder /out/tf-admission-webhook /usr/local/bin/tf-admission-webhook

USER tf
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/tf-admission-webhook"]
