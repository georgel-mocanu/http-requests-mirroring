# HTTP Requests Mirroring - Optimized Version

This is an optimized version of the AWS http-requests-mirroring application with significant performance improvements focused on reducing TCP resets and improving connection efficiency.

## Key Optimizations

### 1. Global HTTP Client with Connection Pooling

**Before (Original):**
```go
// Created a NEW client for EVERY request
httpClient := &http.Client{}
resp, rErr := httpClient.Do(forwardReq)
```

**After (Optimized):**
```go
// Single global client with connection pooling
var httpClient *http.Client  // Initialized once at startup
resp, rErr := httpClient.Do(forwardReq)
```

### 2. Configurable Connection Pool Settings

New command-line flags for tuning:

| Flag | Default | Description |
|------|---------|-------------|
| `-max-idle-conns` | 1000 | Maximum idle connections across all hosts |
| `-max-idle-conns-per-host` | 500 | Maximum idle connections per destination host |
| `-idle-conn-timeout` | 90s | How long idle connections stay in the pool |
| `-request-timeout` | 60s | Overall request timeout |

### 3. Response Body Draining

**Before:**
```go
defer resp.Body.Close()  // Body never read - connection cannot be reused
```

**After:**
```go
io.Copy(io.Discard, resp.Body)  // Drain body to enable keep-alive
resp.Body.Close()
```

### 4. Optimized Transport Settings

- HTTP keep-alive enabled
- TCP keep-alive probes configured
- TLS handshake timeout
- Response header timeout
- HTTP/2 support enabled

## Expected Performance Improvements

| Metric | Original | Optimized |
|--------|----------|-----------|
| TCP RST packets | High (~1500+) | Low (~50-100) |
| New TCP connections/sec | 1 per request | Minimal (reused) |
| TLS handshakes | 1 per request | Minimal (reused) |
| Memory usage | Higher | Lower |
| Latency | Higher | Lower |

## Usage

```bash
# Basic usage (same as original)
./http-requests-mirroring \
  -destination "https://target-server.com" \
  -filter-request-port 80

# With connection pool tuning
./http-requests-mirroring \
  -destination "https://target-server.com" \
  -filter-request-port 80 \
  -max-idle-conns 2000 \
  -max-idle-conns-per-host 1000 \
  -idle-conn-timeout 120s \
  -request-timeout 30s

# With percentage filtering (unchanged from original)
./http-requests-mirroring \
  -destination "https://target-server.com" \
  -filter-request-port 80 \
  -percentage 50 \
  -percentage-by remoteaddr
```

## All Command-Line Flags

### Original Flags
| Flag | Default | Description |
|------|---------|-------------|
| `-destination` | "" | Destination URL for forwarded requests |
| `-percentage` | 100 | Percentage of requests to forward (0-100) |
| `-percentage-by` | "" | Filter by "header" or "remoteaddr" |
| `-percentage-by-header` | "" | Header name when percentage-by is "header" |
| `-filter-request-port` | 80 | Port to capture traffic from |
| `-keep-host-header` | false | Preserve original Host header |

### New Optimization Flags
| Flag | Default | Description |
|------|---------|-------------|
| `-max-idle-conns` | 1000 | Max idle connections (total) |
| `-max-idle-conns-per-host` | 500 | Max idle connections per host |
| `-idle-conn-timeout` | 90s | Idle connection timeout |
| `-request-timeout` | 60s | Request timeout |
| `-max-concurrent-requests` | 10000 | Max concurrent forwarded request goroutines |
| `-max-body-size` | 10485760 | Max request body size in bytes (10MB) |
| `-snap-len` | 65535 | Packet capture snapshot length in bytes |
| `-shutdown-timeout` | 10s | Max time to wait for in-flight requests during shutdown |
| `-max-buffered-pages` | 50000 | Max TCP reassembly pages buffered in memory (0=unlimited) |

## Building

```bash
# Update dependencies and build (CGO_ENABLED=1 is required for libpcap bindings)
go mod tidy
CGO_ENABLED=1 go build -o http-requests-mirroring main.go
```

### Running locally

```bash
./http-requests-mirroring \
  -destination "https://your-target.example.com" \
  -filter-request-port 80
```

**Note**: The binary is now named `http-requests-mirroring` (consistent with the CloudFormation deployment).

## Technical Details

### Why the Original Had TCP Resets

1. **No Connection Reuse**: Creating `&http.Client{}` per request meant each request opened a new TCP connection
2. **Undrained Response Bodies**: Without reading the response body, HTTP keep-alive cannot work
3. **Default Pool Limits**: Go's default `MaxIdleConnsPerHost: 2` is too low for high-throughput scenarios
4. **No Timeouts**: Missing timeouts could lead to resource exhaustion

### How This Version Fixes It

1. **Single Global Client**: One `http.Client` instance reuses connections via its internal pool
2. **Body Draining**: `io.Copy(io.Discard, resp.Body)` ensures the full response is consumed
3. **Tuned Pool**: Higher limits for idle connections prevent pool exhaustion
4. **Proper Timeouts**: Per-request `context.WithTimeout` and client-level timeouts prevent resource exhaustion
5. **Thread-Safe Sampling**: Uses `math/rand/v2` which is inherently safe for concurrent use
6. **Goroutine Limiter**: Semaphore channel caps concurrent forwarded requests to prevent OOM
7. **Body Size Limit**: `io.LimitReader` prevents oversized POST bodies from exhausting memory
8. **Graceful Shutdown**: Signal handling (SIGINT/SIGTERM) flushes the assembler before exit
9. **Rate-Limited Logging**: All error paths use rate-limited logging to prevent log flooding

## Development

### Building with Make

A `Makefile` is provided for convenient development:

```bash
make build          # Build the application
make status         # Show build and environment info
make clean          # Clean build artifacts
make help           # Show all available commands
```

### Deployment

This application is designed to be deployed via the provided CloudFormation templates:

- `replay-handler-cloudformation.yaml` — Base template
- `acc-*.yaml` — Pre-configured for acceptance/staging environments
- `prod-*.yaml` — Pre-configured for production environments

**Important**: The templates now include `go mod tidy` and error checking during build.

### Troubleshooting

- Check service status: `systemctl status replay-handler`
- View logs: `journalctl -u replay-handler -f`
- Check `/var/log/replay-handler.log` on the EC2 instances
- Verify VXLAN interface: `ip link show vxlan0`
- Restart the service: `systemctl restart replay-handler`

## License

BSD-3-Clause License (same as original)
