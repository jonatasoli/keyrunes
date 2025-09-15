# Build stage
FROM rust:latest as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1001 keyrunes

# Set working directory
WORKDIR /app

# Copy Cargo files for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (cached layer)
RUN cargo build --release && rm -rf src

# Copy source code
COPY src ./src
COPY migrations ./migrations
COPY templates ./templates

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1001 keyrunes

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/keyrunes /usr/local/bin/keyrunes
COPY --from=builder /app/target/release/cli /usr/local/bin/keyrunes-cli

# Copy runtime files
COPY --from=builder /app/migrations ./migrations
COPY --from=builder /app/templates ./templates

# Create directories
RUN mkdir -p /app/static && \
    chown -R keyrunes:keyrunes /app

# Switch to app user
USER keyrunes

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Environment variables
ENV RUST_LOG=info
ENV PORT=3000

# Run the application
CMD ["keyrunes"]
