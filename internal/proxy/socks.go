package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"ferry/internal/egress"
)

type dialFunc func(context.Context, egress.Identity, string, string) (net.Conn, error)

func readN(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

// defaultRelayIdle closes a relayed connection once no bytes have moved in
// either direction for this long, so abandoned connections release their slot.
const defaultRelayIdle = 10 * time.Minute

type activeReader struct {
	r    io.Reader
	last *atomic.Int64
}

func (a activeReader) Read(b []byte) (int, error) {
	n, err := a.r.Read(b)
	if n > 0 {
		a.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func relay(ctx context.Context, idle time.Duration, left, right net.Conn, leftReader io.Reader) {
	stop := context.AfterFunc(ctx, func() { left.Close(); right.Close() })
	defer stop()
	defer left.Close()
	defer right.Close()

	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		tick := time.NewTicker(idle / 4)
		defer tick.Stop()
		for {
			select {
			case <-finished:
				return
			case now := <-tick.C:
				if now.Sub(time.Unix(0, last.Load())) >= idle {
					left.Close()
					right.Close()
					return
				}
			}
		}
	}()
	leftReader = activeReader{leftReader, &last}
	var rightReader io.Reader = activeReader{right, &last}

	done := make(chan struct{})
	pump := func(dst net.Conn, src io.Reader) {
		if _, err := io.Copy(dst, src); err != nil {
			left.Close()
			right.Close()
		} else if w, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = w.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go func() { pump(right, leftReader); close(done) }()
	pump(left, rightReader)
	<-done
}

func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func serveSOCKS(ctx context.Context, idle time.Duration, c net.Conn, r *bufio.Reader, requireAuth bool, authenticate authenticateFunc,
	dial dialFunc) error {
	defer c.Close()
	if v, err := r.ReadByte(); err != nil || v != 5 {
		return errors.New("invalid SOCKS5 greeting")
	}
	num, err := r.ReadByte()
	if err != nil {
		return err
	}
	methods, err := readN(r, int(num))
	if err != nil {
		return err
	}
	want := byte(0)
	if requireAuth {
		want = 2
	}
	accepted := false
	for _, offered := range methods {
		accepted = accepted || offered == want
	}
	if !accepted {
		_, err = c.Write([]byte{5, 255})
		return err
	}
	if _, err := c.Write([]byte{5, want}); err != nil {
		return err
	}
	var who egress.Identity
	if want == 2 {
		v, e1 := r.ReadByte()
		uLen, e2 := r.ReadByte()
		if v != 1 || e1 != nil || e2 != nil {
			return errors.New("invalid SOCKS5 authentication")
		}
		u, err := readN(r, int(uLen))
		if err != nil {
			return err
		}
		pLen, err := r.ReadByte()
		if err != nil {
			return err
		}
		p, err := readN(r, int(pLen))
		if err != nil {
			return err
		}
		var valid bool
		who, valid = authenticate(string(u), string(p))
		if !valid {
			_, err = c.Write([]byte{1, 1})
			return err
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return err
		}
	}
	h, err := readN(r, 4)
	if err != nil {
		return err
	}
	if h[0] != 5 || h[2] != 0 {
		return socksReply(c, 1)
	}
	if h[1] != 1 {
		return socksReply(c, 7)
	}
	var host string
	switch h[3] {
	case 1:
		b, err := readN(r, 4)
		if err != nil {
			return err
		}
		host = netip.AddrFrom4([4]byte(b)).String()
	case 3:
		l, err := r.ReadByte()
		if err != nil || l == 0 {
			return socksReply(c, 8)
		}
		b, err := readN(r, int(l))
		if err != nil {
			return err
		}
		host = string(b)
	default:
		return socksReply(c, 8)
	}
	p, err := readN(r, 2)
	if err != nil || binary.BigEndian.Uint16(p) == 0 {
		return socksReply(c, 1)
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	port := strconv.Itoa(int(binary.BigEndian.Uint16(p)))
	up, err := dial(ctx, who, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return socksReply(c, 4)
	}
	defer up.Close()
	if err := socksReply(c, 0); err != nil {
		return fmt.Errorf("send SOCKS5 response: %w", err)
	}
	_ = c.SetDeadline(time.Time{})
	relay(ctx, idle, c, up, r)
	return nil
}
