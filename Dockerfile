FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev linux-headers

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o vpn-agent ./cmd/agent

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates wireguard-tools iproute2

WORKDIR /root/

# Copy binary
COPY --from=builder /app/vpn-agent .

# Expose port
EXPOSE 8080

# Run (requires privileged mode for WireGuard)
CMD ["./vpn-agent"]
