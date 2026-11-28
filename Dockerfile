# Stage 1: Build static Go binary
FROM golang:1.23-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/athena-shield ./cmd/athena

# Stage 2: Minimal runtime image that auto-fixes /data volume ownership and drops to non-root user athena
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata libcap su-exec \
    && addgroup -g 10001 -S athena \
    && adduser -u 10001 -S -G athena -h /app -s /sbin/nologin athena

WORKDIR /app
COPY --from=builder /out/athena-shield /app/athena-shield
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN sed -i 's/\r$//' /app/docker-entrypoint.sh \
    && chmod 0755 /app/docker-entrypoint.sh \
    && setcap 'cap_net_bind_service=+ep' /app/athena-shield \
    && mkdir -p /data \
    && chown -R athena:athena /app /data

ENV DATA_DIR=/data \
    HTTP_PORT=80 \
    HTTPS_PORT=443 \
    DASHBOARD_PORT=1081

VOLUME ["/data"]
EXPOSE 80 443 1081

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:${DASHBOARD_PORT:-1081}/healthz || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
