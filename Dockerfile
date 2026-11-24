# Stage 1: Build static Go binary
FROM golang:1.23-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/athena-shield ./cmd/athena

# Stage 2: Minimal runtime image (Alpine root so binding ports 80/443 works out-of-the-box in Docker/Portainer)
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/athena-shield /app/athena-shield

ENV DATA_DIR=/data \
    HTTP_PORT=80 \
    HTTPS_PORT=443 \
    DASHBOARD_PORT=1081

VOLUME ["/data"]
EXPOSE 80 443 1081

ENTRYPOINT ["/app/athena-shield"]
