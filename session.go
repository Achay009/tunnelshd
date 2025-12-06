package main

import (
	"net"

	"github.com/hashicorp/yamux"
)

type Auth struct {
	Version   string
	Subdomain string
	AuthToken string
}

type CloseWriter interface {
	CloseWrite() error
}

// whats really the point of this class
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
