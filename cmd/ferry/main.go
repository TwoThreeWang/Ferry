package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ferry/internal/admin"
	"ferry/internal/egress"
	"ferry/internal/proxy"
	"ferry/internal/store"
	"ferry/internal/vpngate"
)

func env(name, fallback string) string {
	if x := os.Getenv(name); x != "" {
		return x
	}
	return fallback
}

// proxyAddress is the proxy address shown in the console's examples.
// FERRY_PROXY_ADDRESS overrides it, for example when Docker publishes the
// proxy on a different host port or on a LAN address.
func proxyAddress(listen net.Addr) string {
	if x := os.Getenv("FERRY_PROXY_ADDRESS"); x != "" {
		return x
	}
	host, port, err := net.SplitHostPort(listen.String())
	if err != nil {
		return "127.0.0.1:7928"
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func run(ctx context.Context) error {
	dir := env("FERRY_DATA", "./ferry-data")
	lock, err := store.Lock(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	s, err := store.Open(dir)
	if err != nil {
		return err
	}
	if len(os.Args) == 2 && os.Args[1] == "reset-admin" {
		if err := admin.Reset(s); err != nil {
			return err
		}
		fmt.Println("管理员已重置，请配置新的初始化凭据，再启动服务。")
		return nil
	}
	if len(os.Args) == 2 && os.Args[1] == "init-token" {
		token, err := admin.InitToken(s)
		if err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	}
	if err := admin.EnsureBootstrap(s, os.Getenv("FERRY_SETUP_TOKEN_FILE")); err != nil {
		return err
	}
	tunnels := os.Getenv("FERRY_ENABLE_TUNNELS") == "1"
	if tunnels {
		if err := vpngate.Prepare(ctx); err != nil {
			return err
		}
	}
	var proxyTLS *tls.Config
	cert, key := os.Getenv("FERRY_TLS_CERT"), os.Getenv("FERRY_TLS_KEY")
	if cert != "" || key != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return err
		}
		proxyTLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pool := egress.New(ctx, s, tunnels)
	ln, err := net.Listen("tcp", env("FERRY_ADMIN_LISTEN", "127.0.0.1:8787"))
	if err != nil {
		return err
	}
	defer ln.Close()
	p, err := net.Listen("tcp", env("FERRY_PROXY_LISTEN", "127.0.0.1:7928"))
	if err != nil {
		return err
	}
	defer p.Close()
	console := admin.New(pool, s, proxyAddress(p.Addr()))
	adminHTTP := &http.Server{Handler: console.Handler(), ReadHeaderTimeout: 8 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 32768}
	go pool.Run()
	go console.Run(ctx)
	failed := make(chan error, 2)
	go func() {
		if proxyTLS != nil {
			failed <- adminHTTP.Serve(tls.NewListener(ln, proxyTLS))
		} else {
			failed <- adminHTTP.Serve(ln)
		}
	}()
	go func() {
		failed <- proxy.Serve(ctx, p, pool, proxyTLS)
	}()
	log.Printf("admin %s, proxy %s, VPN tunnels %t", ln.Addr(), p.Addr(), tunnels)
	select {
	case <-ctx.Done():
	case err = <-failed:
	}
	cancel()
	adminHTTP.Close()
	pool.FlushEvents()
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "token" {
		fmt.Println(store.NewToken())
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}
