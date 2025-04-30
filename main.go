package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Client represents a connected user with network-level flow control
// Uses buffered channels and deadlines to prevent slow consumers from blocking the system
type Client struct {
	conn    net.Conn    // Owns the connection lifecycle
	name    string      // Immutable after registration
	send    chan string // Buffered to handle bursty traffic (size matches avg write quota)
	timeout *time.Timer // Uses timer.Reset pattern for activity tracking
}

// Global state is contained to match process lifetime requirements
// All access is synchronised through mutexes or atomics
var (
	clients   = make(map[net.Conn]*Client) // Connection-as-key enables O(1) lookups
	broadcast = make(chan string)          // Fan-out channel pattern
	mu        sync.Mutex
	metrics   = struct { // Lock-free counters for observability
		connections atomic.Int64  // Tracks live connections
		bytesSent   atomic.Uint64 // Counts application-layer bytes
		bytesRecv   atomic.Uint64 // Excludes protocol overhead
		errors      atomic.Uint64
	}{}
)

func main() {
	// Transport-layer configuration
	listenConfig := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Disable Nagle's algorithm for low-latency messaging
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
				// Enable keepalive to detect dead connections
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
			})
		},
	}

	// TLS configuration with modern settings
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal("Certificate error:", err)
	}

	// TLS 1.3-ready configuration with forward-secure ciphers
	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	// Create listener with transport-layer settings
	tcpListener, err := listenConfig.Listen(context.Background(), "tcp", ":8080")
	if err != nil {
		log.Fatal("Listen failed:", err)
	}
	tlsListener := tls.NewListener(tcpListener, tlsConfig)
	defer tlsListener.Close()

	// Start UDP server
	go startUDPServer()

	// Metrics endpoint
	go func() {
		http.HandleFunc("/metrics", metricsHandler)
		log.Fatal(http.ListenAndServe(":6060", nil))
	}()

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go handleSignals(cancel)

	log.Println("Chat server started (TCP+TLS :8080, UDP :8081)")

	go handleBroadcast()
	// Main accept loop follows listener.Accept pattern with error resilience
	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default: // Log but continue on transient errors
				log.Println("Accept error:", err)
			}
			continue
		}
		go handleClient(conn) // Goroutine per conn matches Go's concurrency model
	}
}

// handleClient manages full lifecycle of a TCP connection using scanner pattern
func handleClient(conn net.Conn) {
	defer conn.Close()
	metrics.connections.Add(1)
	defer metrics.connections.Add(-1)

	client := &Client{
		conn:    conn,
		send:    make(chan string, 100), // Buffered channel
		timeout: time.NewTimer(5 * time.Minute),
	}

	// Get username
	fmt.Fprint(conn, "Enter name: ")
	name, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		metrics.errors.Add(1)
		return
	}
	client.name = strings.TrimSpace(name)

	// Registration
	mu.Lock()
	clients[conn] = client
	mu.Unlock()
	broadcast <- fmt.Sprintf("%s joined", client.name)

	// Write pump uses channel receive
	go func() {
		for msg := range client.send { // Channel close triggers exit
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) // Fail-fast on stuck writes
			n, err := fmt.Fprintln(conn, msg)
			metrics.bytesSent.Add(uint64(n)) // Counts actual bytes written
			if err != nil {
				break // Exit on first error (connection state is terminal)
			}
		}
	}()

	// Read pump uses scanner to handle message boundaries
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() { // Scanner defaults to line breaks
		client.timeout.Reset(5 * time.Minute) // Idle timeout sliding window
		msg := scanner.Text()
		metrics.bytesRecv.Add(uint64(len(msg))) // Counts payload bytes
		broadcast <- fmt.Sprintf("%s: %s", client.name, msg)
	}

	// Cleanup
	client.timeout.Stop()
	mu.Lock()
	delete(clients, conn)
	mu.Unlock()
	broadcast <- fmt.Sprintf("%s left", client.name)
	close(client.send)

	// Timeout goroutine uses channel receive for connection cleanup
	go func() {
		<-client.timeout.C // Blocks until timeout or timer.Stop()
		conn.Close()       // Forces read loop exit
	}()
}

// handleBroadcast implements non-blocking fan-out using select-default pattern
func handleBroadcast() {
	for msg := range broadcast { // Range until channel close
		mu.Lock()
		for _, client := range clients {
			select {
			case client.send <- msg: // Fast path
			default: // Protects against slow consumers
				log.Printf("Client %s buffer full", client.name)
			}
		}
		mu.Unlock()
	}
}

// startUDPServer handles connectionless messaging with simple echo
// Note: UDP requires application-level session management
func startUDPServer() {
	pc, err := net.ListenPacket("udp", ":8081")
	if err != nil {
		log.Fatal("UDP failed:", err) // Fatal matches process-level concern
	}
	defer pc.Close() // Ensures release of network resources

	buf := make([]byte, 1024) // Reuse buffer to reduce allocs
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			continue // UDP is connectionless, continue on errors
		}
		log.Printf("UDP[%s]: %s", addr, buf[:n])
		pc.WriteTo([]byte("UDP echo: "+string(buf[:n])), addr) // No error handling matches UDP best-effort
	}
}

// metricsHandler exposes counters in simple text format
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "active_connections %d\n", metrics.connections.Load())
	fmt.Fprintf(w, "bytes_sent %d\n", metrics.bytesSent.Load())
	fmt.Fprintf(w, "bytes_received %d\n", metrics.bytesRecv.Load())
	fmt.Fprintf(w, "errors_total %d\n", metrics.errors.Load())
}

// handleSignals converts OS signals to context cancellation
// Grace period allows in-flight requests to complete
func handleSignals(cancel context.CancelFunc) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")
	cancel()                    // Propagates through context
	time.Sleep(2 * time.Second) // Tradeoff: Fast shutdown vs message loss
	os.Exit(0)                  // Terminate remaining goroutines
}
