package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"ferry/internal/egress"
	"ferry/internal/store"
)

func testProxy(t *testing.T, p proxy, cfg *tls.Config) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.ctx = ctx
	done := make(chan struct{})
	go func() { _ = serveProxy(ctx, l, p, cfg); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return l.Addr().String()
}

func TestHTTPAndTLSProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Remove") != "" {
			t.Error("received proxy-only headers")
		}
		w.Header().Add("Connection", "X-Remove")
		w.Header().Add("X-Remove", "private")
		fmt.Fprint(w, "http-ok")
	}))
	defer origin.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "https-ok")
	}))
	defer secure.Close()
	d := &net.Dialer{Timeout: time.Second}
	up := &http.Transport{DialContext: d.DialContext}
	defer up.CloseIdleConnections()
	addr := testProxy(t, proxy{
		auth: credentials{"test", "pass"},
		send: func(_ egress.Identity, r *http.Request) (*http.Response, error) { return up.RoundTrip(r) },
		dial: func(ctx context.Context, _ egress.Identity, network, address string) (net.Conn, error) {
			return d.DialContext(ctx, network, address)
		},
	},
		&tls.Config{Certificates: secure.TLS.Certificates, MinVersion: tls.VersionTLS12})
	pc := secure.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	for _, tc := range []struct{ proxyScheme, target, want string }{
		{"http", origin.URL, "http-ok"},
		{"http", secure.URL, "https-ok"},
		{"https", secure.URL, "https-ok"},
	} {
		t.Run(tc.proxyScheme+"-"+tc.want, func(t *testing.T) {
			proxyURL := &url.URL{Scheme: tc.proxyScheme, Host: addr, User: url.UserPassword("test", "pass")}
			tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: pc}
			defer tr.CloseIdleConnections()
			req, _ := http.NewRequest(http.MethodGet, tc.target, nil)
			if tc.want == "http-ok" {
				req.Header.Set("Connection", "X-Remove")
				req.Header.Set("X-Remove", "private")
			}
			r, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Body.Close()
			b, _ := io.ReadAll(r.Body)
			if r.StatusCode != 200 || string(b) != tc.want || r.Header.Get("X-Remove") != "" {
				t.Fatalf("status=%d body=%q leaked=%q", r.StatusCode, b, r.Header.Get("X-Remove"))
			}
		})
	}
	tr := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr})}
	defer tr.CloseIdleConnections()
	r, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 407 {
		t.Fatalf("unauthenticated request returned %d", r.StatusCode)
	}
}

func TestSOCKSAndBufferedTunnelOnSamePort(t *testing.T) {
	destination := make(chan string, 2)
	dial := func(_ context.Context, _ egress.Identity, _, address string) (net.Conn, error) {
		destination <- address
		left, right := net.Pipe()
		go func() {
			defer right.Close()
			b, err := readN(right, 4)
			if err == nil {
				_, _ = right.Write(b)
			}
		}()
		return left, nil
	}
	addr := testProxy(t, proxy{dial: dial}, nil)
	c, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	hello := []byte{5, 1, 0, 5, 1, 0, 3, 11}
	hello = append(hello, []byte("example.org")...)
	hello = append(hello, 1, 187, 'p', 'i', 'n', 'g')
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	reply, err := readN(c, 16)
	if err != nil || !bytes.Equal(reply, []byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 'p', 'i', 'n', 'g'}) {
		t.Fatalf("SOCKS reply %v, %v", reply, err)
	}
	if got := <-destination; got != "example.org:443" {
		t.Fatalf("domain not passed to the tunnel: %q", got)
	}
	connect, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connect.Close()
	_ = connect.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(connect, "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\nping")
	b := bufio.NewReader(connect)
	r, err := http.ReadResponse(b, &http.Request{Method: http.MethodConnect})
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("CONNECT response %v, %v", r, err)
	}
	payload, err := readN(b, 4)
	if err != nil || string(payload) != "ping" {
		t.Fatalf("CONNECT buffered payload: %q, %v", payload, err)
	}
}

func TestProxyWithoutVPN(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := egress.New(ctx, state, false)
	addr := testProxy(t, proxy{dial: m.Dial, send: m.RoundTrip}, nil)
	c := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr})},
	}
	r, err := c.Get("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 502 {
		t.Fatalf("expected 502 without VPN, got %d", r.StatusCode)
	}
	s, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = s.Write([]byte{5, 1, 0, 5, 1, 0, 1, 1, 1, 1, 1, 0, 80})
	reply, err := readN(s, 12)
	if err != nil || reply[3] != 4 {
		t.Fatalf("expected SOCKS failure without VPN, got %v (%v)", reply, err)
	}
}

func TestProxyCredentialsAndSelectionAcrossProtocols(t *testing.T) {
	seen := make(chan egress.Identity, 2)
	p := proxy{
		verify: func(u, p string) (egress.Identity, bool) {
			return egress.Identity{Account: "client", Region: "JP"}, u == "client.JP" && p == "pass"
		},
		dial: func(_ context.Context, who egress.Identity, _, _ string) (net.Conn, error) {
			seen <- who
			return nil, egress.ErrUnavailable
		},
	}
	addr := testProxy(t, p, nil)
	t.Run("HTTP CONNECT", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set("Proxy-Authorization", "Basic Y2xpZW50LkpQOnBhc3M=")
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		if w.Code != 502 || (<-seen).Region != "JP" {
			t.Fatalf("selector not propagated, status %d", w.Code)
		}
	})
	t.Run("SOCKS5", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		conn.Write([]byte{5, 1, 2})
		g, err := readN(conn, 2)
		if err != nil || g[1] != 2 {
			t.Fatalf("auth selection %v %v", g, err)
		}
		buf := append([]byte{1, 9}, []byte("client.JP")...)
		buf = append(buf, 4)
		buf = append(buf, []byte("pass")...)
		conn.Write(buf)
		g, err = readN(conn, 2)
		if err != nil || g[1] != 0 {
			t.Fatalf("auth response %v %v", g, err)
		}
		target := "example.com"
		buf = append([]byte{5, 1, 0, 3, byte(len(target))}, []byte(target)...)
		buf = append(buf, 1, 187)
		conn.Write(buf)
		g, err = readN(conn, 10)
		if err != nil || g[1] != 4 {
			t.Fatalf("expected unavailable reply %v %v", g, err)
		}
		select {
		case who := <-seen:
			if who.Region != "JP" || strings.TrimSpace(who.Account) != "client" {
				t.Fatal("selector not propagated")
			}
		case <-time.After(time.Second):
			t.Fatal("no SOCKS dial")
		}
	})
}
