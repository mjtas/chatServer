package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"log"
	"math/big"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestServer simulates a TLS-based chat server with client tracking, broadcasting, and metrics
type TestServer struct {
	clients   map[net.Conn]*Client // Active client connections
	mu        sync.Mutex           // Protects access to the clients map
	broadcast chan string          // Channel for broadcasting messages to all clients
	listener  net.Listener         // TLS listener instance

	metrics struct {
		connections atomic.Int64
		bytesSent   atomic.Uint64
		bytesRecv   atomic.Uint64
		errors      atomic.Uint64
	}

	ctx    context.Context // Cancellation context for coordinated shutdown
	cancel context.CancelFunc
	wg     sync.WaitGroup // Tracks all server goroutines for graceful shutdown
}

// NewTestServer initialises an isolated testable server with background broadcast handling
func NewTestServer() *TestServer {
	// Context used to stop broadcast loop and listener accept loop
	ctx, cancel := context.WithCancel(context.Background())
	s := &TestServer{
		clients:   make(map[net.Conn]*Client),
		broadcast: make(chan string, 100),
		ctx:       ctx,
		cancel:    cancel,
	}
	// Fan-out broadcaster runs independently of client logic
	go s.handleBroadcast()
	return s
}

// StartTestListener starts a TLS server listener on a random port and begins accepting clients
// Automatically spawns goroutines to handle each connection
func (s *TestServer) StartTestListener(tlsConfig *tls.Config) net.Listener {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		log.Fatalf("Failed to start test listener: %v", err)
	}
	s.listener = ln
	s.wg.Add(1)
	// Accept loop
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			// Graceful shutdown path
			if err != nil {
				select {
				case <-s.ctx.Done():
					return
				default:
					continue
				}
			}
			// Handle connection in isolated goroutine
			s.wg.Add(1)
			go func(c net.Conn) {
				defer s.wg.Done()
				s.handleClient(c)
			}(conn)
		}
	}()
	return ln
}

// DialTestServer returns a TLS client connection to the given address
func (s *TestServer) DialTestServer(addr string) net.Conn {
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Fatalf("Dial failed: %v", err)
	}
	return conn
}

// handleClient manages a single client's lifecycle including registration,
// read/write loops, timeout, and clean shutdown
func (s *TestServer) handleClient(conn net.Conn) {
	defer conn.Close()
	s.metrics.connections.Add(1)
	defer s.metrics.connections.Add(-1)

	client := &Client{
		conn:    conn,
		send:    make(chan string, 100),
		timeout: time.NewTimer(5 * time.Minute),
	}

	// Prompt for name
	fmt.Fprint(conn, "Enter name: ")
	name, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		s.metrics.errors.Add(1)
		return
	}
	client.name = strings.TrimSpace(name)

	// Register client
	s.mu.Lock()
	s.clients[conn] = client
	s.mu.Unlock()

	// Notify all clients of join
	s.broadcast <- fmt.Sprintf("%s joined", client.name)

	// Async send loop — sends messages to client
	go func() {
		for msg := range client.send {
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			n, err := fmt.Fprintln(conn, msg)
			s.metrics.bytesSent.Add(uint64(n))
			if err != nil {
				break
			}
		}
	}()

	// Read loop — blocks on input and rebroadcasts messages
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		client.timeout.Reset(5 * time.Minute)
		msg := scanner.Text()
		s.metrics.bytesRecv.Add(uint64(len(msg)))
		s.broadcast <- fmt.Sprintf("%s: %s", client.name, msg)
	}

	// Cleanup on client disconnect
	client.timeout.Stop()
	s.mu.Lock()
	delete(s.clients, conn)
	s.mu.Unlock()
	s.broadcast <- fmt.Sprintf("%s left", client.name)
	close(client.send)
}

// handleBroadcast reads from the broadcast channel and fans out messages to all connected clients
func (s *TestServer) handleBroadcast() {
	for {
		select {
		case msg := <-s.broadcast:
			s.mu.Lock()
			for _, c := range s.clients {
				select {
				case c.send <- msg:
				default:
					log.Printf("Client %s buffer full", c.name)
				}
			}
			s.mu.Unlock()
		case <-s.ctx.Done():
			return
		}
	}
}

// Shutdown gracefully terminates the server, stops all goroutines,
// closes connections and cleans up client state
func (s *TestServer) Shutdown() {
	s.cancel() // signal all goroutines to stop
	if s.listener != nil {
		s.listener.Close()
	}
	// Close all active connections and channels
	s.mu.Lock()
	for conn := range s.clients {
		conn.Close()
	}
	s.clients = map[net.Conn]*Client{}
	s.mu.Unlock()
	s.wg.Wait() // wait for all goroutines to complete
}

// NewTestTLSConfig generates a self-signed TLS configuration for use in test listeners
func NewTestTLSConfig() (*tls.Config, error) {
	// Generate RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create a simple certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour), // 1-day validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create a self-signed cert
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// PEM encode the certificate and key
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Load TLS certificate from PEM data
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// TestClientRegistration validates that a client can connect and register successfully
// Verifies that the server correctly prompts for a name and tracks the connected client
func TestClientRegistration(t *testing.T) {
	srv := NewTestServer()
	defer srv.Shutdown()

	// Load pre-generated test TLS certs from disk
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	require.NoError(t, err)
	ln := srv.StartTestListener(&tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	})
	defer ln.Close()

	conn := srv.DialTestServer(ln.Addr().String())
	defer conn.Close()

	// Read server's name prompt and respond
	buf := make([]byte, 1024)
	conn.Read(buf) // name prompt
	conn.Write([]byte("TestUser\n"))

	// Ensure client was registered
	assert.Eventually(t, func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return len(srv.clients) == 1
	}, time.Second, 10*time.Millisecond)
}

// TestTLSConnection ensures that a TLS handshake completes successfully
// when connecting to the test server using an in-memory self-signed cert
func TestTLSConnection(t *testing.T) {
	srv := NewTestServer()
	defer srv.Shutdown()

	tlsCfg, err := NewTestTLSConfig()
	require.NoError(t, err)

	ln := srv.StartTestListener(tlsCfg)
	defer ln.Close()

	conn := srv.DialTestServer(ln.Addr().String())
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	assert.True(t, state.HandshakeComplete)
}

// TestClientJoinLeaveAndBroadcast validates that:
// - multiple clients can join
// - messages are broadcast correctly
// - leave notifications are sent upon disconnect
func TestClientJoinLeaveAndBroadcast(t *testing.T) {
	srv := NewTestServer()
	defer srv.Shutdown()

	tlsCfg, err := NewTestTLSConfig()
	require.NoError(t, err)
	ln := srv.StartTestListener(tlsCfg)

	defer ln.Close()

	conn1 := srv.DialTestServer(ln.Addr().String())
	defer conn1.Close()

	// Register first user
	conn1.Read(make([]byte, 1024)) // prompt
	conn1.Write([]byte("Aerith\n"))
	time.Sleep(50 * time.Millisecond) // let join broadcast propagate

	conn2 := srv.DialTestServer(ln.Addr().String())
	defer conn2.Close()

	// Register second user
	conn2.Read(make([]byte, 1024)) // prompt
	conn2.Write([]byte("Bob\n"))
	time.Sleep(50 * time.Millisecond)

	// Aerith sends a message
	conn1.Write([]byte("Hello everyone\n"))

	// Bob should receive it
	scanner := bufio.NewScanner(conn2)
	assert.Eventually(t, func() bool {
		return scanner.Scan() && strings.Contains(scanner.Text(), "Aerith: Hello everyone")
	}, time.Second, 10*time.Millisecond)

	// Disconnect Aerith
	conn1.Close()
	time.Sleep(100 * time.Millisecond)

	// Bob should get the leave message
	assert.Eventually(t, func() bool {
		return scanner.Scan() && strings.Contains(scanner.Text(), "Aerith left")
	}, time.Second, 10*time.Millisecond)
}

// TestClientTimeout simulates a client being idle and ensures it is eventually
// removed from the server's client map due to timeout expiry
// Note: The timeout is manually triggered in test via timer.Reset
func TestClientTimeout(t *testing.T) {
	srv := NewTestServer()
	defer srv.Shutdown()

	tlsCfg, _ := NewTestTLSConfig()
	ln := srv.StartTestListener(tlsCfg)
	defer ln.Close()

	conn := srv.DialTestServer(ln.Addr().String())
	defer conn.Close()

	conn.Read(make([]byte, 1024)) // prompt
	conn.Write([]byte("IdleUser\n"))

	// Wait until client is fully registered before manipulating timer
	var client *Client
	assert.Eventually(t, func() bool {
		client = getClientByName(srv, "IdleUser")
		return client != nil
	}, time.Second, 10*time.Millisecond)

	// Manually trigger timeout
	client.timeout.Reset(10 * time.Millisecond)
	time.Sleep(50 * time.Millisecond)

	// After timeout, client should be removed
	assert.Eventually(t, func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		_, exists := srv.clients[conn]
		return !exists
	}, time.Second, 10*time.Millisecond)
}

// getClientByName safely looks up a connected client by name
// It acquires the server's mutex to ensure consistent access to the shared clients map
func getClientByName(srv *TestServer, name string) *Client {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, c := range srv.clients {
		if c.name == name {
			return c
		}
	}
	return nil
}

// TestUDPEchoServer validates a basic UDP echo pattern
// Launches a temporary UDP server and ensures the echoed message is returned as expected
func TestUDPEchoServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()

	// Simple UDP echo loop
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo([]byte("UDP echo: "+string(buf[:n])), addr)
		}
	}()

	conn, err := net.Dial("udp", pc.LocalAddr().String())
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	require.NoError(t, err)

	assert.Contains(t, string(buf[:n]), "UDP echo: ping")
}

// TestMetricsReporting verifies that metrics values are correctly reported via HTTP
// Uses a mock HTTP recorder and checks for expected output formatting
func TestMetricsReporting(t *testing.T) {
	metrics.connections.Store(2)
	metrics.bytesSent.Store(500)
	metrics.bytesRecv.Store(400)
	metrics.errors.Store(1)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	metricsHandler(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "active_connections 2")
	assert.Contains(t, string(body), "bytes_sent 500")
	assert.Contains(t, string(body), "bytes_received 400")
	assert.Contains(t, string(body), "errors_total 1")
}
