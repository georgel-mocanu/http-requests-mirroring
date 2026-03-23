# HTTP Requests Mirroring - Makefile
# Optimized VXLAN-based AWS Traffic Mirroring replay tool

.PHONY: all build clean test run help

# Default target
all: build

# Build the optimized binary
build:
	go mod tidy
	go build -o http-requests-mirroring main.go
	@echo "✅ Build successful! Binary: ./http-requests-mirroring"
	@ls -lh http-requests-mirroring

# Clean build artifacts
clean:
	rm -f http-requests-mirroring
	go clean
	@echo "🧹 Cleaned build artifacts"

# Run with default settings (requires -destination flag)
run: build
	@echo "Usage: ./http-requests-mirroring -destination https://example.com [other flags]"
	@echo "Example:"
	@echo "  ./http-requests-mirroring -destination https://test.example.com -filter-request-port 80"

# Run tests (if any)
test:
	go test -v ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  build     - Build the application (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  run       - Build and show usage"
	@echo "  test      - Run tests"
	@echo "  all       - Build the application"
	@echo ""
	@echo "Common flags:"
	@echo "  -destination string          Destination URL"
	@echo "  -filter-request-port int     Port to filter (default 80)"
	@echo "  -percentage float            Forward percentage (default 100)"
	@echo "  -max-idle-conns int          Max idle connections (default 1000)"

# Show current git status and build info
status:
	@echo "=== Build Information ==="
	@go version
	@echo "Module: $$(grep '^module' go.mod)"
	@echo "Binary size: $$(ls -lh http-requests-mirroring 2>/dev/null | awk '{print $$5}' || echo 'Not built yet')"
	@echo "Last modified: $$(ls -l http-requests-mirroring 2>/dev/null | awk '{print $$6,$$7,$$8}' || echo 'Not built yet')"

