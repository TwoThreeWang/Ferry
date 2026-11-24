package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"ferry/internal/egress"
)

// maxConnections caps concurrent client connections across all accounts.
const maxConnections = 512

type credentials struct{ user, pass string }

func (a credentials) matches(u, p string) bool {
	compare := func(x, y string) int {
		hx, hy := sha256.Sum256([]byte(x)), sha256.Sum256([]byte(y))
		return subtle.ConstantTimeCompare(hx[:], hy[:])
	}
	return compare(a.user, u)&compare(a.pass, p) == 1
}

type authenticateFunc func(string, string) (egress.Identity, bool)

type Backend interface {
	Authenticate(user, password string) (egress.Identity, bool)
	Dial(ctx context.Context, who egress.Identity, network, addr string) (net.Conn, error)
	RoundTrip(who egress.Identity, request *http.Request) (*http.Response, error)
}

type proxy struct {
	verify authenticateFunc
	auth   credentials
	dial   dialFunc
	send   func(egress.Identity, *http.Request) (*http.Response, error)
	ctx    context.Context
	idle   time.Duration // relay idle timeout; zero means defaultRelayIdle
}

func (p proxy) idleTimeout() time.Duration {
	if p.idle > 0 {
		return p.idle
	}
	return defaultRelayIdle
}

func (p proxy) authenticate(user, pass string) (egress.Identity, bool) {
	if p.verify != nil {
		return p.verify(user, pass)
	}
	return egress.Identity{}, p.auth.matches(user, pass)
}

func stripHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, k := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(k))
		}
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}

func (p proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var who egress.Identity
	if p.auth.user != "" || p.verify != nil {
		req := &http.Request{Header: http.Header{"Authorization": r.Header.Values("Proxy-Authorization")}}
		u, pass, ok := req.BasicAuth()
		var valid bool
		who, valid = p.authenticate(u, pass)
		if !ok || !valid {
			w.Header().Set("Proxy-Authenticate", `Basic realm="VPNGate proxy"`)
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r, who)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Hostname() == "" || r.URL.User != nil {
		http.Error(w, "Use an absolute HTTP URL or CONNECT", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Upgrade") != "" {
		http.Error(w, "HTTP Upgrade requires CONNECT", http.StatusNotImplemented)
		return
	}
	req := r.Clone(r.Context())
	req.RequestURI = ""
	req.Host = req.URL.Host
	req.Close = false
	stripHop(req.Header)
	req.Trailer = nil
	resp, err := p.send(who, req)
	if err != nil {
		http.Error(w, "VPN upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	stripHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		panic(http.ErrAbortHandler)
	}
}

func (p proxy) connect(w http.ResponseWriter, r *http.Request, who egress.Identity) {
	h, port, err := net.SplitHostPort(r.RequestURI)
	pn, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || h == "" || pn == 0 {
		http.Error(w, "CONNECT requires host:port", http.StatusBadRequest)
		return
	}
	up, err := p.dial(r.Context(), who, "tcp", net.JoinHostPort(h, port))
	if err != nil {
		http.Error(w, "VPN upstream unavailable", http.StatusBadGateway)
		return
	}
	defer up.Close()
	client, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	_ = client.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buf.Flush(); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	relay(p.ctx, p.idleTimeout(), client, up, buf.Reader)
}

type connSlot struct {
	net.Conn
	buf     *bufio.Reader
	release func()
	once    sync.Once
}

func (c *connSlot) Read(b []byte) (int, error) {
	if c.buf.Buffered() > 0 {
		return c.buf.Read(b)
	}
	return c.Conn.Read(b)
}

func (c *connSlot) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
func (c *connSlot) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return c.Close()
}

type httpQueue struct {
	addr net.Addr
	in   chan net.Conn
	done chan struct{}
	once sync.Once
}

func (q *httpQueue) Accept() (net.Conn, error) {
	select {
	case <-q.done:
		return nil, net.ErrClosed
	case c := <-q.in:
		return c, nil
	}
}
func (q *httpQueue) Addr() net.Addr { return q.addr }
func (q *httpQueue) Close() error   { q.once.Do(func() { close(q.done) }); return nil }

func Serve(ctx context.Context, l net.Listener, backend Backend, tlsConfig *tls.Config) error {
	return serveProxy(ctx, l, proxy{
		verify: backend.Authenticate,
		dial:   backend.Dial,
		send:   backend.RoundTrip,
		ctx:    ctx,
	}, tlsConfig)
}

func serveProxy(ctx context.Context, l net.Listener, p proxy, tlsConfig *tls.Config) error {
	q := &httpQueue{addr: l.Addr(), in: make(chan net.Conn), done: make(chan struct{})}
	s := &http.Server{
		Handler: p, ReadHeaderTimeout: 8 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 64 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	defer s.Close()
	go func() { _ = s.Serve(q) }()
	stop := context.AfterFunc(ctx, func() { l.Close(); s.Close() })
	defer stop()
	defer l.Close()
	limit := make(chan struct{}, maxConnections)
	var backoff time.Duration
	var lastFull time.Time
	for {
		raw, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return err
			}
			// Like net/http: transient failures such as EMFILE must not stop the proxy.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			log.Printf("proxy accept: %v; retrying in %v", err, backoff)
			select {
			case <-time.After(backoff):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		backoff = 0
		select {
		case limit <- struct{}{}:
		default:
			_ = raw.Close()
			if now := time.Now(); now.Sub(lastFull) > 10*time.Second {
				lastFull = now
				log.Printf("proxy: %d connections in use, refusing %s", maxConnections, raw.RemoteAddr())
			}
			continue
		}
		go func() {
			r := bufio.NewReader(raw)
			c := &connSlot{Conn: raw, buf: r, release: func() { <-limit }}
			ownership := false
			defer func() {
				if !ownership {
					c.Close()
				}
			}()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			_ = c.SetDeadline(time.Now().Add(8 * time.Second))
			b, err := r.Peek(1)
			if err != nil {
				return
			}
			if b[0] == 5 {
				_ = serveSOCKS(ctx, p.idleTimeout(), c, r, p.auth.user != "" || p.verify != nil, p.authenticate, p.dial)
				return
			}
			var incoming net.Conn = c
			if b[0] == 22 {
				if tlsConfig == nil {
					return
				}
				incoming = tls.Server(c, tlsConfig)
			}
			_ = c.SetDeadline(time.Time{})
			select {
			case q.in <- incoming:
				ownership = true
			case <-q.done:
			case <-ctx.Done():
			}
		}()
	}
}
