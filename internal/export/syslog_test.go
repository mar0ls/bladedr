package export

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSendSyslogTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	received := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received <- buf[:n]
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	payload := []byte(`{"id":"abc"}`)
	if err := sendSyslog(ctx, map[string]string{"address": ln.Addr().String()}, payload); err != nil {
		t.Fatalf("sendSyslog: %v", err)
	}

	select {
	case msg := <-received:
		s := string(msg)
		if !strings.HasPrefix(s, "<134>1 ") {
			t.Errorf("message missing RFC5424 priority/version prefix: %q", s)
		}
		if !strings.Contains(s, "bladedr - observation -") {
			t.Errorf("message missing app/msgid fields: %q", s)
		}
		if !strings.HasSuffix(s, string(payload)+"\n") {
			t.Errorf("message does not end with the payload + newline: %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never received a message")
	}
}

func TestSendSyslogUDP(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	payload := []byte(`{"id":"def"}`)
	if err := sendSyslog(ctx, map[string]string{"network": "udp", "address": conn.LocalAddr().String()}, payload); err != nil {
		t.Fatalf("sendSyslog: %v", err)
	}

	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server never received a datagram: %v", err)
	}
	if !strings.Contains(string(buf[:n]), string(payload)) {
		t.Errorf("datagram missing payload: %q", buf[:n])
	}
}

func TestSendSyslogValidation(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		config map[string]string
	}{
		{"unsupported network", map[string]string{"network": "unix", "address": "127.0.0.1:514"}},
		{"address with no port", map[string]string{"address": "127.0.0.1"}},
		{"empty address", map[string]string{}},
	}
	for _, c := range cases {
		err := sendSyslog(ctx, c.config, []byte("x"))
		if err == nil {
			t.Errorf("%s: want an error, got nil", c.name)
			continue
		}
		var perm permanentError
		if !errors.As(err, &perm) {
			t.Errorf("%s: a config problem must be a permanentError (not retried forever), got %T: %v", c.name, err, err)
		}
	}
}

func TestSendSyslogUnreachableIsRetryable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	// Nothing listens here (port 0 bound-and-closed pattern): a connection failure to a
	// reachable-looking address, unlike a bad config, should NOT be permanentError — the
	// outbox retries it since the target may come back.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // now nothing is listening on this address

	err = sendSyslog(ctx, map[string]string{"address": addr}, []byte("x"))
	if err == nil {
		t.Fatal("want a dial error")
	}
	var perm permanentError
	if errors.As(err, &perm) {
		t.Errorf("a connection failure must be retryable, not permanentError: %v", err)
	}
}
