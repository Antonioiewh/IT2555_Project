FROM golang:1.22-alpine AS builder

# Install build dependencies including glibc compatibility
RUN apk add --no-cache git make bash gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /go/src/github.com/percona/orchestrator

# Clone the repository
RUN git clone https://github.com/percona/orchestrator.git . && \
    git checkout v3.2.6

# Set Go environment variables
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64

# Fix SQLite3 compilation issues on Alpine
ENV CGO_CFLAGS="-D_LARGEFILE64_SOURCE"

# Fix the missing dependencies and module issues
RUN cd go && \
    go get github.com/mattn/go-sqlite3@v1.14.7 && \
    go mod download && \
    go mod tidy && \
    go mod vendor

# Build orchestrator binary with SQLite3 tags
RUN cd go && \
    go build -mod=vendor -tags "sqlite_omit_load_extension" -ldflags "-X main.AppVersion=3.2.6" -o ../orchestrator ./cmd/orchestrator

# Verify the binary was created and check what resources exist
RUN ls -la ./orchestrator && ./orchestrator --version
RUN find . -name "*.html" -o -name "*.js" -o -name "*.css" | head -20

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates mysql-client curl bash sqlite

# Create orchestrator user
RUN adduser -D -s /bin/sh orchestrator

# Create necessary directories
RUN mkdir -p /etc/orchestrator /var/lib/orchestrator /var/log/orchestrator /usr/local/orchestrator

# Copy the binary from builder stage
COPY --from=builder /go/src/github.com/percona/orchestrator/orchestrator /usr/local/bin/orchestrator

# Copy web resources (templates, static files)
COPY --from=builder /go/src/github.com/percona/orchestrator/resources /usr/local/orchestrator/resources

# Copy discovery script
COPY ./discover.sh /usr/local/bin/discover.sh
COPY ./orchestrator.conf.json /etc/orchestrator/orchestrator.conf.json

# Set proper ownership
RUN chown -R orchestrator:orchestrator /etc/orchestrator /var/lib/orchestrator /var/log/orchestrator /usr/local/orchestrator
RUN chown orchestrator:orchestrator /etc/orchestrator/orchestrator.conf.json
RUN chmod 400 /etc/orchestrator/orchestrator.conf.json

# Make binaries executable
RUN chmod +x /usr/local/bin/orchestrator /usr/local/bin/discover.sh

# Switch to orchestrator user
USER orchestrator

# Set working directory to where resources are located
WORKDIR /usr/local/orchestrator

# Expose ports
EXPOSE 3000 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3000/api/status || exit 1

# # Set entrypoint
ENTRYPOINT ["/usr/local/bin/discover.sh"]
