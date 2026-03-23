// Original Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Modification Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Optimized version with connection pooling, reduced TCP resets,
// goroutine limiting, and graceful shutdown.

package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"hash/crc64"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/examples/util"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/gopacket/gopacket/tcpassembly/tcpreader"
)

var fwdDestination = flag.String("destination", "", "Destination of the forwarded requests.")
var fwdPerc = flag.Float64("percentage", 100, "Must be between 0 and 100.")
var fwdBy = flag.String("percentage-by", "", "Can be empty. Otherwise, valid values are: header, remoteaddr.")
var fwdHeader = flag.String("percentage-by-header", "", "If percentage-by is header, then specify the header here.")
var reqPort = flag.Int("filter-request-port", 80, "Must be between 0 and 65535.")
var keepHostHeader = flag.Bool("keep-host-header", false, "Keep Host header from original request.")

var maxIdleConns = flag.Int("max-idle-conns", 1000, "Maximum number of idle connections across all hosts.")
var maxIdleConnsPerHost = flag.Int("max-idle-conns-per-host", 500, "Maximum number of idle connections per host.")
var idleConnTimeout = flag.Duration("idle-conn-timeout", 90*time.Second, "Idle connection timeout.")
var requestTimeout = flag.Duration("request-timeout", 60*time.Second, "Overall request timeout.")
var maxConcurrentRequests = flag.Int("max-concurrent-requests", 10000, "Maximum number of concurrent forwarded requests.")
var maxBodySize = flag.Int64("max-body-size", 10*1024*1024, "Maximum request body size in bytes (default 10MB).")
var snapLen = flag.Int("snap-len", 65535, "Packet capture snapshot length in bytes.")
var shutdownTimeout = flag.Duration("shutdown-timeout", 10*time.Second, "Max time to wait for in-flight requests during shutdown.")
var maxBufferedPages = flag.Int("max-buffered-pages", 50000, "Max TCP reassembly pages buffered in memory (0=unlimited).")

var httpClient *http.Client

// trimmedDestination is computed once at startup from fwdDestination.
var trimmedDestination string

// shutdownCtx is cancelled on SIGINT/SIGTERM to propagate cancellation to in-flight requests.
var shutdownCtx context.Context
var shutdownCancel context.CancelFunc

var crc64Table = crc64.MakeTable(0xC96C5795D7870F42)

var forwardSem chan struct{}

// hopByHopHeaders are removed before forwarding per RFC 2616 section 13.5.1.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// rateLimiter provides per-category rate-limited logging.
type rateLimiter struct {
	last atomic.Int64
}

var (
	rlStreamRead    = &rateLimiter{}
	rlBodyRead      = &rateLimiter{}
	rlBodyOversize  = &rateLimiter{}
	rlConcurrency   = &rateLimiter{}
	rlForwardCreate = &rateLimiter{}
	rlForwardExec   = &rateLimiter{}
	rlResponseDrain = &rateLimiter{}
)

const errorLogInterval = 5 * time.Second

func (rl *rateLimiter) logf(format string, args ...interface{}) {
	now := time.Now().Unix()
	last := rl.last.Load()
	if now-last > int64(errorLogInterval.Seconds()) {
		if rl.last.CompareAndSwap(last, now) {
			log.Printf(format, args...)
		}
	}
}

func initHTTPClient() {
	transport := &http.Transport{
		MaxIdleConns:        *maxIdleConns,
		MaxIdleConnsPerHost: *maxIdleConnsPerHost,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     *idleConnTimeout,

		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,

		DisableKeepAlives:  false,
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}

	httpClient = &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	log.Printf("HTTP client initialized: MaxIdleConns=%d, MaxIdleConnsPerHost=%d, IdleConnTimeout=%v, RequestTimeout=%v",
		*maxIdleConns, *maxIdleConnsPerHost, *idleConnTimeout, *requestTimeout)
}

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream handles the actual decoding of HTTP requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run()
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			rlStreamRead.logf("Error reading HTTP request from %v -> %v: %v", h.net.Src(), h.net.Dst(), err)
			tcpreader.DiscardBytesToEOF(&h.r)
			return
		} else {
			reqSourceIP := h.net.Src().String()
			reqDestinationPort := h.transport.Dst().String()

			body, bErr := io.ReadAll(io.LimitReader(req.Body, *maxBodySize+1))
			req.Body.Close()
			if bErr != nil {
				rlBodyRead.logf("Error reading request body from %v: %v", reqSourceIP, bErr)
				continue
			}
			if int64(len(body)) > *maxBodySize {
				rlBodyOversize.logf("Dropping oversized request body (%d bytes) from %v", len(body), reqSourceIP)
				continue
			}

			select {
			case forwardSem <- struct{}{}:
				go func() {
					defer func() { <-forwardSem }()
					forwardRequest(req, reqSourceIP, reqDestinationPort, body)
				}()
			default:
				rlConcurrency.logf("Dropping request from %v: concurrency limit (%d) reached", reqSourceIP, *maxConcurrentRequests)
			}
		}
	}
}

func forwardRequest(req *http.Request, reqSourceIP string, reqDestinationPort string, body []byte) {
	if *fwdPerc != 100 {
		if *fwdBy == "" {
			if rand.Float64()*100 > *fwdPerc {
				return
			}
		} else {
			strForSeed := ""
			if *fwdBy == "header" {
				strForSeed = req.Header.Get(*fwdHeader)
			} else {
				strForSeed = reqSourceIP
			}
			if strForSeed == "" {
				strForSeed = reqSourceIP
			}
			hash := crc64.Checksum([]byte(strForSeed), crc64Table)
			if hash%100 >= uint64(*fwdPerc) {
				return
			}
		}
	}

	uri := strings.TrimLeft(req.RequestURI, "/")
	var targetURL string
	if uri == "" {
		targetURL = trimmedDestination
	} else {
		targetURL = trimmedDestination + "/" + uri
	}

	ctx, cancel := context.WithTimeout(shutdownCtx, *requestTimeout)
	defer cancel()

	forwardReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		rlForwardCreate.logf("Failed to create forward request to %s: %v", targetURL, err)
		return
	}

	for header, values := range req.Header {
		if hopByHopHeaders[header] {
			continue
		}
		for _, value := range values {
			forwardReq.Header.Add(header, value)
		}
	}

	forwardReq.Header.Add("X-Forwarded-For", reqSourceIP)
	if forwardReq.Header.Get("X-Forwarded-Port") == "" {
		forwardReq.Header.Set("X-Forwarded-Port", reqDestinationPort)
	}
	if forwardReq.Header.Get("X-Forwarded-Proto") == "" {
		forwardReq.Header.Set("X-Forwarded-Proto", "http")
	}
	if forwardReq.Header.Get("X-Forwarded-Host") == "" {
		forwardReq.Header.Set("X-Forwarded-Host", req.Host)
	}

	if *keepHostHeader {
		forwardReq.Host = req.Host
	}

	resp, rErr := httpClient.Do(forwardReq)
	if rErr != nil {
		rlForwardExec.logf("Forward request to %s failed: %v", targetURL, rErr)
		return
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		rlResponseDrain.logf("Error draining response body from %s: %v", targetURL, err)
	}
}

// openTCPClient listens on TCP 4789 for NLB health checks.
func openTCPClient(ctx context.Context) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", ":4789")
	if err != nil {
		log.Println("Error listening on TCP:", err)
		os.Exit(1)
	}
	defer ln.Close()
	log.Println("Listening on TCP 4789")

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("Error accepting connection:", err)
			continue
		}
		conn.Close()
	}
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	flag.Parse()

	if *fwdDestination == "" {
		log.Fatal("flag -destination is required and must not be empty")
	}
	if *fwdPerc > 100 || *fwdPerc < 0 {
		err = fmt.Errorf("flag percentage is not between 0 and 100. Value: %f", *fwdPerc)
	} else if *fwdBy != "" && *fwdBy != "header" && *fwdBy != "remoteaddr" {
		err = fmt.Errorf("flag percentage-by (%s) is not valid", *fwdBy)
	} else if *fwdBy == "header" && *fwdHeader == "" {
		err = fmt.Errorf("flag percentage-by is set to header, but percentage-by-header is empty")
	} else if *reqPort > 65535 || *reqPort < 0 {
		err = fmt.Errorf("flag filter-request-port is not between 0 and 65535. Value: %d", *reqPort)
	}
	if err != nil {
		log.Fatal(err)
	}

	trimmedDestination = strings.TrimRight(*fwdDestination, "/")

	shutdownCtx, shutdownCancel = context.WithCancel(context.Background())
	defer shutdownCancel()

	initHTTPClient()

	forwardSem = make(chan struct{}, *maxConcurrentRequests)
	log.Printf("Concurrency limiter initialized: max %d concurrent forwarded requests", *maxConcurrentRequests)

	log.Printf("Starting capture on interface vxlan0 (snaplen=%d)", *snapLen)
	handle, err = pcap.OpenLive("vxlan0", int32(*snapLen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	BPFFilter := fmt.Sprintf("tcp and dst port %d", *reqPort)
	if err := handle.SetBPFFilter(BPFFilter); err != nil {
		log.Fatal(err)
	}

	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	if *maxBufferedPages > 0 {
		assembler.MaxBufferedPagesTotal = *maxBufferedPages
		assembler.MaxBufferedPagesPerConnection = *maxBufferedPages / 10
		log.Printf("TCP reassembly memory limits: total=%d pages, per-connection=%d pages",
			assembler.MaxBufferedPagesTotal, assembler.MaxBufferedPagesPerConnection)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go openTCPClient(shutdownCtx)

	log.Println("Reading packets")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	flushTicker := time.NewTicker(30 * time.Second)
	defer flushTicker.Stop()

	for {
		select {
		case <-sigCh:
			log.Println("Received shutdown signal, stopping packet capture...")
			handle.Close()
			log.Println("Flushing assembler...")
			assembler.FlushAll()
			log.Printf("Waiting up to %v for %d in-flight requests to complete...", *shutdownTimeout, len(forwardSem))
			drainDone := make(chan struct{})
			go func() {
				for i := 0; i < cap(forwardSem); i++ {
					forwardSem <- struct{}{}
				}
				close(drainDone)
			}()
			select {
			case <-drainDone:
				log.Println("All in-flight requests completed")
			case <-time.After(*shutdownTimeout):
				log.Printf("Timed out waiting for in-flight requests after %v", *shutdownTimeout)
				shutdownCancel()
			}
			log.Println("Shutdown complete")
			return

		case packet := <-packets:
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-flushTicker.C:
			assembler.FlushOlderThan(time.Now().Add(-30 * time.Second))
		}
	}
}
