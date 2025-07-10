# Multi-stage build for CodexSentinel
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o codex ./cmd/codex

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata git

# Create non-root user
RUN addgroup -g 1001 -S codex && \
    adduser -u 1001 -S codex -G codex

# Set working directory
WORKDIR /workspace

# Copy binary from builder stage
COPY --from=builder /app/codex /usr/local/bin/codex

# Copy assets
COPY --from=builder /app/assets /usr/local/share/codexsentinel/assets

# Change ownership
RUN chown -R codex:codex /workspace

# Switch to non-root user
USER codex

# Set environment variables
ENV PATH="/usr/local/bin:$PATH"
ENV CODECSENTINEL_ASSETS="/usr/local/share/codexsentinel/assets"

# Default command
ENTRYPOINT ["codex"]

# Default arguments
CMD ["--help"] 