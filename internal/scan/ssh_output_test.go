package scan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestCapturedOutputCapsWrittenBytes(t *testing.T) {
	c := &capturedOutput{limit: 10}
	if n, err := c.Write([]byte("01234")); n != 5 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if n, err := c.Write([]byte("56789")); n != 5 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if c.truncated {
		t.Fatal("writing exactly the limit must not count as truncated")
	}
	if c.buf.String() != "0123456789" {
		t.Fatalf("buf = %q", c.buf.String())
	}
	if n, err := c.Write([]byte("X")); n != 1 || err != nil {
		t.Fatalf("Write = %d, %v (io.Writer must still report the full length written)", n, err)
	}
	if !c.truncated {
		t.Fatal("writing past the limit must be recorded as truncated")
	}
	if c.buf.Len() != 10 {
		t.Fatalf("buf grew past the limit: %d bytes", c.buf.Len())
	}
}

func TestCapturedOutputDetectsTruncationAcrossWrites(t *testing.T) {
	// A single Write larger than the limit must be caught even though the running
	// total only ever reflects one call.
	c := &capturedOutput{limit: 4}
	if _, err := c.Write(bytes.Repeat([]byte("a"), 100)); err != nil {
		t.Fatal(err)
	}
	if !c.truncated || c.buf.Len() != 4 {
		t.Fatalf("truncated=%v buf.Len=%d, want truncated with 4 bytes kept", c.truncated, c.buf.Len())
	}
}

// sshExecServer is a minimal in-process SSH server that answers every "exec"
// request by calling handle with the requested command and writing back whatever
// it returns. It exists to drive ssh.Client.NewSession/Run/Start the same way a
// real scan target would, so the truncation guard in run() is exercised through
// the actual code path (session.Stdout/Stderr), not a reimplementation of it.
func sshExecServer(t *testing.T, handle func(cmd string) (stdout, stderr []byte, exit uint32)) *ssh.Client {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		nConn, err := ln.Accept()
		if err != nil {
			return
		}
		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(reqs)
		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				return
			}
			go func(channel ssh.Channel, in <-chan *ssh.Request) {
				defer channel.Close()
				for req := range in {
					if req.Type != "exec" {
						if req.WantReply {
							_ = req.Reply(false, nil)
						}
						continue
					}
					var payload struct{ Command string }
					_ = ssh.Unmarshal(req.Payload, &payload)
					_ = req.Reply(true, nil)
					stdout, stderr, exit := handle(payload.Command)
					_, _ = channel.Write(stdout)
					_, _ = channel.Stderr().Write(stderr)
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{exit}))
					return
				}
			}(channel, requests)
		}
	}()

	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("unused")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestRunReturnsOutputUnderLimit(t *testing.T) {
	client := sshExecServer(t, func(cmd string) ([]byte, []byte, uint32) {
		return []byte("hello " + cmd), nil, 0
	})
	out, err := run(client, "world", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello world" {
		t.Fatalf("out = %q", out)
	}
}

// TestRunRefusesOversizedRemoteOutput is the regression test for the DoS finding:
// a scan target is not fully trusted, and run() is what every command sent to it
// funnels through. A target that returns more than maxRemoteOutputBytes — whether
// compromised, misbehaving, or just unlucky — must fail the command with a clear
// error instead of growing the control plane's memory without bound.
func TestRunRefusesOversizedRemoteOutput(t *testing.T) {
	oversized := bytes.Repeat([]byte("A"), maxRemoteOutputBytes+1)
	client := sshExecServer(t, func(cmd string) ([]byte, []byte, uint32) {
		return oversized, nil, 0
	})
	out, err := run(client, "big", nil)
	if err == nil {
		t.Fatalf("oversized output was accepted: %d bytes", len(out))
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("err = %v, want a size-limit diagnostic", err)
	}
	if out != nil {
		t.Fatalf("a refused command must not hand back a partial result: %d bytes", len(out))
	}
}

func TestRunRefusesOversizedRemoteStderr(t *testing.T) {
	oversized := bytes.Repeat([]byte("E"), maxRemoteOutputBytes+1)
	client := sshExecServer(t, func(cmd string) ([]byte, []byte, uint32) {
		return []byte("ok"), oversized, 1
	})
	if _, err := run(client, "big-stderr", nil); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("err = %v, want a size-limit diagnostic", err)
	}
}
