package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/hashicorp/yamux"
)

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

	runClient(ControlPort, ControlHost, opts.command, opts)
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

	authReq := &Auth{
		Subdomain: opts.subdomain,
		Version:   MajorMinor(),
		AuthToken: opts.authtoken,
	}

	jsonData, err := json.Marshal(authReq)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return fmt.Errorf("failed to create json: %w", err)
	}

	// Create and send upgrade request
	req, err := http.NewRequest("POST", "/", bytes.NewBuffer(jsonData))
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

	listener := &SessionListener{sess}

	log.Println("Waiting for incoming connections...")

	httpServer := &http.Server{
		Handler: proxy,
	}

	// This will block until the session closes
	return httpServer.Serve(listener)

}

// bufferedConn wraps a connection with a buffered reader
type bufferedConn struct {
	io.Reader
	net.Conn
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.Reader.Read(p)
}
