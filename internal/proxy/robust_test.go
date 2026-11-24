package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"ferry/internal/egress"
)

// failOnce returns EMFILE from its first Accept, like a process out of file descriptors.
type failOnce struct {
	net.Listener
	once sync.Once
}

func (l *failOnce) Accept() (net.Conn, error) {
	var failed bool
	l.once.Do(func() { failed = true })
	if failed {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}
	}
	return l.Listener.Accept()
}

func socksHandshake(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0, 5, 1, 0, 1, 93, 184, 216, 34, 0, 80}); err != nil {
		t.Fatal(err)
	}
	reply, err := readN(c, 12)
	if err != nil || !bytes.Equal(reply, []byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("SOCKS reply %v, %v", reply, err)
	}
	_ = c.SetDeadline(time.Time{})
	return c
}

func TestAcceptErrorDoesNotStopProxy(t *testing.T) {
	inner, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	dial := func(context.Context, egress.Identity, string, string) (net.Conn, error) {
		left, right := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, right) }()
		return left, nil
	}
	go func() { done <- serveProxy(ctx, &failOnce{Listener: inner}, proxy{dial: dial, ctx: ctx}, nil) }()
	c := socksHandshake(t, inner.Addr().String())
	c.Close()
	select {
	case err := <-done:
		t.Fatalf("proxy stopped: %v", err)
	default:
	}
	cancel()
	<-done
}

func TestIdleRelayIsClosed(t *testing.T) {
	upstreamClosed := make(chan struct{})
	dial := func(context.Context, egress.Identity, string, string) (net.Conn, error) {
		left, right := net.Pipe()
		go func() {
			b := make([]byte, 16)
			for {
				n, err := right.Read(b)
				if err != nil {
					close(upstreamClosed)
					return
				}
				_, _ = right.Write(b[:n])
			}
		}()
		return left, nil
	}
	c := socksHandshake(t, testProxy(t, proxy{dial: dial, idle: 200 * time.Millisecond}, nil))
	defer c.Close()
	// Traffic keeps the relay open past the idle limit.
	for range 4 {
		time.Sleep(100 * time.Millisecond)
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("hi")); err != nil {
			t.Fatal(err)
		}
		if b, err := readN(c, 2); err != nil || string(b) != "hi" {
			t.Fatalf("active relay closed: %q, %v", b, err)
		}
	}
	select {
	case <-upstreamClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("idle relay was not closed")
	}
}
