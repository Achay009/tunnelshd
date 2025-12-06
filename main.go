package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

type bufferedConn struct {
	io.Reader
	net.Conn
}

var (
	ControlHost string = "start.tunnelsh.top"
	ControlPort string = "8443"
)

func main() {
	opts, err := ParseArgs()

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// flag.Parse()

	if opts.command == "" {
		log.Fatal("Usage: tunnelsh <local-port>\nExample: tunnelsh 8080")
	}

	runClient(ControlHost, ControlPort, opts.command, opts)
}

func runClient(host, port, localPort string, opts *Options) {

	log.Printf("Starting tunnel client for localhost:%s", localPort)
	for {
		if err := connectAndRunTunnel(host, port, localPort, opts); err != nil {
			log.Printf("Connection failed: %v - retrying in 3 seconds", err)
			time.Sleep(3 * time.Second)
		}
	}
}

func connectAndRunTunnel(host, port, localPort string, opts *Options) error {
	log.Println("Connecting to tunnel server...")
	serverAddr := net.JoinHostPort(host, port)

	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}

	// Connect with TLS
	// log.Printf("Dialing %s", serverAddr)
	log.Println("Dialing Control Server...")
	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	log.Println("Control Server connected...")
	// Make sure we clean up the connection
	defer conn.Close()

	// Set TCP keepalive to detect dead connections
	if tcpConn, ok := conn.NetConn().(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	authReq := &Auth{
		Subdomain: opts.subdomain,
		Version:   MajorMinor(),
		AuthToken: opts.authtoken,
	}

	var buffer bytes.Buffer

	log.Printf("\n--- Created buffer for sending auth req... data (%d bytes) ---\n", buffer.Len())

	encoder := gob.NewEncoder(&buffer)

	if err := encoder.Encode(authReq); err != nil {
		return fmt.Errorf("gob encode error: %w", err)
	}

	log.Printf("\n--- Client Sending Auth req Data (%d bytes) ---\n", buffer.Len())

	// Create and send upgrade request
	req, err := http.NewRequest("POST", "/", &buffer)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// CRITICAL: Use just hostname for Host header (not host:port)
	req.Host = host
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tunnelsh/1.0")
	req.Header.Set("Content-Type", "application/octet-stream")

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
	// i dont know why i did this
	hijackedConn := &bufferedConn{
		Reader: br,
		Conn:   conn,
	}

	// Create session over the hijacked connection
	sess, err := yamux.Server(hijackedConn, ymConfig)
	if err != nil {
		panic(err)
	}

	session := &SessionListener{sess}

	log.Println("Waiting for incoming connections...")
	for {

		// Accept with timeout check
		ch, err := session.Accept()
		if err != nil {
			log.Printf("Error while Accepting connection")
			return fmt.Errorf("session accept error: %w", err)
		}

		// Connect to local service
		localConn, err := net.Dial("tcp", "localhost:"+localPort)
		if err != nil {
			log.Printf("✗ Failed to connect to localhost:%s - %v", localPort, err)
			ch.Close()
			continue
		}
		log.Printf("→ Incoming request, connecting to http://localhost:%s", localPort)
		// log.Println("✓ Connected, proxying traffic")

		// Bridge the connections
		go func() {
			join(localConn, ch)
			log.Println("✓ Request completed")
		}()
	}

}

// bufferedConn wraps a connection with a buffered reader

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
