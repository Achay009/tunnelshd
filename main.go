package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

type CloseWriter interface {
	CloseWrite() error
}

type SessionListener struct {
	*yamux.Session
}

// Close closes the underlying session
func (sl *SessionListener) Close() error {
	return sl.Session.Close()
}

// Close closes the underlying session
func (sl *SessionListener) Accept() (net.Conn, error) {
	return sl.Session.Accept()
}

func (sl *SessionListener) Addr() net.Addr {
	return sl.Session.Addr()
}

// Accept matches the net.Listener signature.
// qmux.Session.Accept returns (Channel, error), and Channel implements net.Conn, so this works.
// func (sl *SessionListener) Accept() (net.Conn, error) {
// 	// return sl.Session.Accept()
// 	channel, err := sl.Session.Accept()
// 	if err != nil {
// 		return nil, err
// 	}

// 	// conn is of type mux.Channel, but since it implements Read/Write/Close,
// 	// we can return it as a net.Conn.
// 	return &ChannelAdapter{channel}, nil
// }

func main() {
	var port = flag.String("p", "8443", "server port to use")
	var host = flag.String("h", "start.tunnelsh.top", "server hostname to use")
	flag.Parse()

	if flag.Arg(0) == "" {
		log.Fatal("Usage: groktunnel <local-port>\nExample: groktunnel 8080")
	}

	runClient(*host, *port, flag.Arg(0))
}

func runClient(host, port, localPort string) {
	log.Printf("Starting tunnel client for localhost:%s", localPort)
	for {
		if err := connectAndRunTunnel(host, port, localPort); err != nil {
			log.Printf("Connection failed: %v - retrying in 3 seconds", err)
			time.Sleep(3 * time.Second)
		}
	}
}

func connectAndRunTunnel(host, port, localPort string) error {
	log.Println("Connecting to tunnel server...")
	serverAddr := net.JoinHostPort(host, port)

	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}

	// Connect with TLS
	log.Printf("Dialing %s", serverAddr)
	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Make sure we clean up the connection
	defer conn.Close()

	// Set TCP keepalive to detect dead connections
	if tcpConn, ok := conn.NetConn().(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Create and send upgrade request
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// CRITICAL: Use just hostname for Host header (not host:port)
	req.Host = host
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tunnelsh/1.0")

	log.Println("Sending upgrade request...")
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("failed to write request: %w", err)
	}

	// Read response
	log.Println("Reading server response...")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, resp.Status)
	}

	// Get public host
	publicHost := resp.Header.Get("X-Public-Host")
	if publicHost == "" {
		return fmt.Errorf("server did not return X-Public-Host header")
	}

	fmt.Printf("\n✓ Tunnel established!\n")
	fmt.Printf("  Local:  http://localhost:%s\n", localPort)
	fmt.Printf("  Public: https://%s\n\n", publicHost)

	ymConfig := yamux.DefaultConfig()
	ymConfig.KeepAliveInterval = 10 * time.Second

	// Create a combined connection that uses the buffered reader
	hijackedConn := &bufferedConn{
		Reader: br,
		Conn:   conn,
	}

	// Create session over the hijacked connection
	// sess := session.New(hijackedConn)

	sess, err := yamux.Server(hijackedConn, ymConfig)
	if err != nil {
		panic(err)
	}

	targetUrl, _ := url.Parse("http://localhost:" + localPort)
	proxy := httputil.NewSingleHostReverseProxy(targetUrl)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Lie to the local app: "This request is definitely for localhost"
		req.Host = fmt.Sprintf("localhost:%s", localPort)

		// Fix Origin for WebSockets/HMR
		req.Header.Set("Origin", fmt.Sprintf("http://localhost:%s", localPort))
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		// Tell the app it's actually running over HTTPS (on the public internet)
		req.Header.Del("Accept-Encoding")
	}

	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 0,
		}).DialContext,
		DisableKeepAlives:  false,
		DisableCompression: true,
		MaxIdleConns:       1,
		IdleConnTimeout:    90 * time.Second,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
	}

	proxy.FlushInterval = 100 * time.Millisecond

	// Error handling for the proxy
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
	}

	// Monitor session health
	// sessionDone := make(chan struct{})
	// go func() {
	// 	sess.
	// 	// close(sessionDone)
	// 	log.Println("Session ended by server")
	// }()

	listener := &SessionListener{sess}

	// defer sess.Close()

	log.Println("Waiting for incoming connections...")

	httpServer := &http.Server{
		Handler: proxy,
	}

	// This will block until the session closes
	return httpServer.Serve(listener)

	// Accept incoming tunnel requests
	// go func() {
	// for {
	// 	select {
	// 	case <-sessionDone:
	// 		return fmt.Errorf("session closed by server")
	// 	default:
	// 	}

	// 	// Accept with timeout check
	// 	ch, err := sess.Accept()
	// 	if err != nil {
	// 		// Check if session is closed
	// 		select {
	// 		case <-sessionDone:
	// 			return fmt.Errorf("session closed: %w", err)
	// 		default:
	// 			return fmt.Errorf("session accept error: %w", err)
	// 		}
	// 	}

	// 	log.Printf("→ Incoming request, connecting to localhost:%s", localPort)

	// 	// Connect to local service
	// 	localConn, err := net.Dial("tcp", "localhost:"+localPort)
	// 	if err != nil {
	// 		log.Printf("✗ Failed to connect to localhost:%s - %v", localPort, err)
	// 		ch.Close()
	// 		continue
	// 	}

	// 	log.Println("✓ Connected, proxying traffic")

	// 	// Bridge the connections
	// 	go func() {
	// 		join(localConn, ch)
	// 		log.Println("✓ Request completed")
	// 	}()
	// }
	// }()
}

// bufferedConn wraps a connection with a buffered reader
type bufferedConn struct {
	io.Reader
	net.Conn
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.Reader.Read(p)
}

func join(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy with explicit flushing to preserve chunked transfer encoding
	copyWithFlush := func(dst io.Writer, src io.Reader, name string) {
		defer wg.Done()

		buf := make([]byte, 32*1024) // 32KB buffer
		totalBytes := int64(0)

		for {
			nr, er := src.Read(buf)
			if nr > 0 {
				totalBytes += int64(nr)
				nw, ew := dst.Write(buf[0:nr])

				// Flush immediately after each write to preserve chunk boundaries
				// This is critical for chunked transfer encoding used by SPA dev servers
				if f, ok := dst.(interface{ Flush() error }); ok {
					if err := f.Flush(); err != nil {
						log.Printf("Copy %s flush error after %d bytes: %v", name, totalBytes, err)
						break
					}
				}

				if ew != nil {
					log.Printf("Copy %s write error after %d bytes: %v", name, totalBytes, ew)
					break
				}
				if nr != nw {
					log.Printf("Copy %s short write: read %d, wrote %d", name, nr, nw)
					break
				}
			}
			if er != nil {
				if er != io.EOF {
					log.Printf("Copy %s read error after %d bytes: %v", name, totalBytes, er)
				}
				break
			}
		}

		// Close write end when done
		if cw, ok := dst.(CloseWriter); ok {
			cw.CloseWrite()
		}
	}

	// Copy from a to b
	go copyWithFlush(b, a, "a->b")

	// Copy from b to a
	go copyWithFlush(a, b, "b->a")

	// Wait for both directions to finish
	wg.Wait()

	// Close both connections
	a.Close()
	b.Close()
}

// func joinold(a io.ReadWriteCloser, b io.ReadWriteCloser) {
// 	var wg sync.WaitGroup
// 	wg.Add(2)

// 	// Copy from a to b
// 	go func() {
// 		defer wg.Done()
// 		n, err := io.Copy(b, a)
// 		if err != nil && err != io.EOF {
// 			log.Printf("Copy a→b error after %d bytes: %v", n, err)
// 		}
// 		// Close write end of b when done reading from a
// 		if cw, ok := b.(CloseWriter); ok {
// 			cw.CloseWrite()
// 		}
// 	}()

// 	// Copy from b to a
// 	go func() {
// 		defer wg.Done()
// 		n, err := io.Copy(a, b)
// 		if err != nil && err != io.EOF {
// 			log.Printf("Copy b→a error after %d bytes: %v", n, err)
// 		}
// 		// Close write end of a when done reading from b
// 		if cw, ok := a.(CloseWriter); ok {
// 			cw.CloseWrite()
// 		}
// 	}()

// 	// Wait for both directions to finish
// 	wg.Wait()

// 	// Close both connections
// 	a.Close()
// 	b.Close()
// }
