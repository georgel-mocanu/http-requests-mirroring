# Optimizations over the Original

This document lists every change made to the original
[aws-samples/http-requests-mirroring](https://github.com/aws-samples/http-requests-mirroring)
application, grouped by category.

---

## Connection Management

### 1. Global HTTP Client with Connection Pooling

The original created a **new `http.Client` for every forwarded request**, which meant
every request opened a fresh TCP connection and never reused it. The optimized
version initializes a single global `http.Client` at startup with a fully
configured `http.Transport`, so connections are pooled and reused across requests.

**Original:**
```go
httpClient := &http.Client{}
resp, rErr := httpClient.Do(forwardReq)
```

**Optimized:**
```go
var httpClient *http.Client  // initialized once at startup via initHTTPClient()
resp, rErr := httpClient.Do(forwardReq)
```

### 2. Tuned Transport Parameters

The original used Go's default transport settings (`MaxIdleConnsPerHost: 2`),
which is far too low for high-throughput traffic mirroring. The optimized
version exposes all pool settings as command-line flags with sensible defaults.

| Setting | Original | Optimized Default |
|---------|----------|-------------------|
| `MaxIdleConns` | 100 (Go default) | 1000 |
| `MaxIdleConnsPerHost` | 2 (Go default) | 500 |
| `MaxConnsPerHost` | unlimited | 1000 |
| `IdleConnTimeout` | 90s (Go default) | 90s (configurable) |
| `DialContext.Timeout` | 30s (Go default) | 30s (explicit) |
| `DialContext.KeepAlive` | 30s (Go default) | 30s (explicit) |
| `TLSHandshakeTimeout` | none | 10s |
| `ResponseHeaderTimeout` | none | 30s |
| `ForceAttemptHTTP2` | true (Go default) | false |

### 3. Response Body Draining

When a response body is not fully read, Go cannot reuse the underlying TCP
connection — it must close it. The original only called `resp.Body.Close()`
without reading, making keep-alive impossible. The optimized version drains
the response body before closing, enabling connection reuse.

**Original:**
```go
defer resp.Body.Close()  // body never read → connection closed
```

**Optimized:**
```go
io.Copy(io.Discard, resp.Body)  // drain body → connection returned to pool
resp.Body.Close()
```

### 4. Redirect Prevention

The original followed redirects by default, which could cause unexpected
behavior when mirroring traffic. The optimized version returns immediately
on redirect responses without following them.

---

## Resource Protection

### 5. Goroutine Concurrency Limiter

The original spawned an unbounded `go forwardRequest(...)` goroutine for every
captured HTTP request. Under high traffic, this could exhaust memory. The
optimized version uses a semaphore channel to cap concurrent goroutines and
drops requests when the limit is reached.

**Original:**
```go
go forwardRequest(req, reqSourceIP, reqDestionationPort, body)
```

**Optimized:**
```go
select {
case forwardSem <- struct{}{}:
    go func() {
        defer func() { <-forwardSem }()
        forwardRequest(req, reqSourceIP, reqDestinationPort, body)
    }()
default:
    // drop request — concurrency limit reached
}
```

### 6. Request Body Size Limit

The original used `ioutil.ReadAll(req.Body)`, which reads the entire body with
no size bound — a single large POST could exhaust memory. The optimized version
caps body reads at a configurable maximum (default 10 MB) and drops oversized
requests.

**Original:**
```go
body, bErr := ioutil.ReadAll(req.Body)
```

**Optimized:**
```go
io.Copy(bodyBuf, io.LimitReader(req.Body, *maxBodySize+1))
if int64(bodyBuf.Len()) > *maxBodySize {
    // drop oversized body
}
```

### 7. Per-Request Timeout via Context

The original had no timeout on forwarded HTTP requests. A slow or unresponsive
destination could hold goroutines and connections indefinitely. The optimized
version wraps each request in a `context.WithTimeout` tied to both the request
timeout and the global shutdown context.

**Original:**
```go
forwardReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
```

**Optimized:**
```go
ctx, cancel := context.WithTimeout(shutdownCtx, *requestTimeout)
defer cancel()
forwardReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, bytes.NewReader(body))
```

### 8. TCP Reassembly Memory Limits

The original placed no limits on the TCP reassembly buffer. The optimized
version caps total buffered pages and per-connection pages to prevent unbounded
memory growth in the packet reassembler.

---

## Reliability

### 9. Graceful Shutdown

The original had no signal handling — the process was killed immediately,
potentially losing in-flight requests. The optimized version catches
`SIGINT`/`SIGTERM`, closes the pcap handle, flushes the assembler, and waits
for in-flight requests to complete (with a configurable timeout).

### 10. Stream Recovery after Parse Errors

The original logged parse errors and continued the loop, but could get stuck
on corrupted data. The optimized version includes a `scanToHTTPMethod()`
function that scans forward byte-by-byte to find the next valid HTTP request
line, recovering from mid-stream restarts or partial captures.

### 11. Health Check Listener Cleanup

The original TCP health check listener (`openTCPClient`) had no shutdown path
and silently ignored accept errors. The optimized version is context-aware and
shuts down cleanly when the application exits.

### 12. Destination Validation

The original did not check for an empty `-destination` flag, which would
silently produce broken URLs. The optimized version fails fast with a clear
error message.

---

## Performance

### 13. Body Buffer Pool (sync.Pool)

The original allocated a new byte slice for every request body. The optimized
version uses a `sync.Pool` of `bytes.Buffer` objects to reduce garbage
collection pressure under high throughput.

### 14. Thread-Safe Random Number Generation

The original called `math/rand.Seed()` and `math/rand.Float64()` from
concurrent goroutines, which is not thread-safe and causes data races. The
optimized version uses `math/rand/v2`, which is safe for concurrent use
without external synchronization.

### 15. Deterministic Percentage Filtering

For `percentage-by` mode, the original seeded a new RNG per request and drew
a random float — this was racy and non-deterministic. The optimized version
uses a pure modulus check on the CRC-64 hash (`hash % 100 >= percentage`),
which is deterministic, thread-safe, and faster.

### 16. Configurable Snapshot Length

The original hardcoded the pcap snapshot length to `8951` bytes, which may
truncate large HTTP requests. The optimized version defaults to `65535` bytes
and makes it configurable via the `-snap-len` flag.

### 17. Configurable Flush Interval

The original used `time.Tick(time.Minute)`, which leaks the underlying ticker.
The optimized version uses `time.NewTicker` with proper cleanup and makes the
interval configurable.

---

## Correctness

### 18. Hop-by-Hop Header Stripping

The original copied all headers from the captured request to the forwarded
request, including hop-by-hop headers (`Connection`, `Keep-Alive`,
`Transfer-Encoding`, etc.) that are meant for a single transport-level
connection. The optimized version strips these per RFC 2616 section 13.5.1.

### 19. URL Construction Fix

The original concatenated destination and request URI directly, which could
produce malformed URLs with double slashes. The optimized version trims
trailing slashes from the destination and leading slashes from the URI before
joining.

**Original:**
```go
url := fmt.Sprintf("%s%s", *fwdDestination, req.RequestURI)
```

**Optimized:**
```go
trimmedDestination = strings.TrimRight(*fwdDestination, "/")
uri := strings.TrimLeft(req.RequestURI, "/")
targetURL = trimmedDestination + "/" + uri
```

### 20. Empty Header Fallback

When `percentage-by` is set to `header` and the specified header is missing
from the request, the original used an empty string for the hash seed —
meaning all such requests would hash identically. The optimized version falls
back to the source IP address.

### 21. Bug Fix in Validation Error Message

The original printed `*fwdPerc` (a float) instead of `*reqPort` (an int) in
the port validation error message.

---

## Code Quality

### 22. Updated gopacket Library

The original used `github.com/google/gopacket`, which is no longer actively
maintained. The optimized version uses `github.com/gopacket/gopacket`, the
community-maintained fork.

### 23. Removed Deprecated `ioutil` Package

Replaced `ioutil.ReadAll` with `io.Copy` + `io.LimitReader`, following Go's
deprecation of the `ioutil` package since Go 1.16.

### 24. Removed `examples/util` Dependency

The original imported `github.com/google/gopacket/examples/util` (a utility
from gopacket's example code). The optimized version parses flags directly.

### 25. Rate-Limited Error Logging

The original used `log.Println` for all errors, which can flood logs and
consume disk space under high error rates. The optimized version uses
per-category rate limiters that log at most once every 5 seconds per category.

### 26. Removed Noisy "Unusable packet" Log

The original logged every non-TCP packet as "Unusable packet", which can be
extremely noisy on a busy interface. The optimized version silently skips them.
