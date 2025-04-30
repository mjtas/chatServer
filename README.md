# chatServer
A high-performance concurrent chat server implementing both TCP/TLS and UDP protocols, designed to demonstrate production-grade Go network programming patterns.

## Features

- **Secure TCP Communication**
    - TLS 1.3-ready with modern cipher suites (ECDHE-ECDSA-AES256-GCM-SHA384)
    - TCP_NODELAY enabled for low-latency messaging
    - Connection keepalive for dead peer detection

- **UDP Echo Service**
    - Simple echo protocol on port 8081
    - Connectionless message handling demonstration

- **Client Management**
    - Buffered channels for flow control (100 message buffer)
    - Activity timeout (5 minutes idle disconnect)
    - Atomic connection metrics tracking

- **Observability**
    - Track active connections, bytes transferred, and errors
    - Non-blocking broadcast system with backpressure detection

- **Operational Excellence**
    - Graceful shutdown with 2-second drain period
    - OS signal handling (SIGINT/SIGTERM)
    - Concurrent-safe resource cleanup

## Prerequisites
- Go 1.20+
- OpenSSL (for certificate generation)
- Basic network utilities (`nc`, `telnet`, `curl`)

## Installation
```bash
# Clone repository
git clone https://github.com/yourusername/go-chat-server.git
cd go-chat-server

# Generate TLS certificates
openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost"

# Build binary
go build -o go-chat-server
```  
## How to use
- Start server:  
```./go-chat-server```
- Connect with TLS Client:  
```bash  
openssl s_client -connect localhost:8080
# Sample session:  
> Enter name: Moira  
< Moira joined  
> Hello!  
< Moira: Hello!  
```
- UDP Echo Test:  
```bash  
echo "test" | nc -u localhost 8081  
# Response: UDP echo: test
```
- Metrics Endpoint:  
```bash  
curl http://localhost:6060/metrics  
# Sample output:  
active_connections 3  
bytes_sent 1429  
bytes_received 892  
errors_total 0  
```
## Testing
- Run comprehensive test suite:  
```go test -test.v```
- TLS handshake validation 
- Concurrent client simulation 
- UDP echo protocol verification 
- Metrics collection accuracy 
- Graceful shutdown sequence

## Graceful Shutdown Sequence
- SIGINT/SIGTERM received
- Stop accepting new connections
- Close all active client connections
- Flush remaining messages (2-second window)
- Release UDP port
- Exit process

## Certificate Management
- Replace self-signed certs with CA-signed certificates
- Set tls.Config.MinVersion = tls.VersionTLS13 in production
- Rotate certificates using Kubernetes secrets or Vault