package main

import (
	"net/http"
	"testing"
	"time"
)

func TestNewHTTPServerLimits(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := newHTTPServer(":8080", handler)

	if server.Addr != ":8080" || server.Handler == nil {
		t.Fatalf("server address or handler not configured: %+v", server)
	}
	if server.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadHeaderTimeout = %s, want 10s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %s, want 30s", server.ReadTimeout)
	}
	if server.WriteTimeout != 5*time.Minute {
		t.Errorf("WriteTimeout = %s, want 5m", server.WriteTimeout)
	}
	if server.IdleTimeout != 2*time.Minute {
		t.Errorf("IdleTimeout = %s, want 2m", server.IdleTimeout)
	}
	if server.MaxHeaderBytes != 1<<20 {
		t.Errorf("MaxHeaderBytes = %d, want %d", server.MaxHeaderBytes, 1<<20)
	}
}
