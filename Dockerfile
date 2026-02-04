# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum* ./
RUN go mod download || true

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
    -o domrecon ./cmd/domrecon

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' domrecon

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/domrecon /app/domrecon

# Copy wordlists
COPY --from=builder /build/internal/scanner/wordlists /app/wordlists

# Copy default config
COPY --from=builder /build/config.yaml /etc/domrecon/config.yaml

# Create directories for templates (to be mounted or downloaded)
RUN mkdir -p /app/nuclei-templates && chown -R domrecon:domrecon /app

USER domrecon

# Expose server port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Default to service mode
ENTRYPOINT ["/app/domrecon"]
CMD ["serve"]
