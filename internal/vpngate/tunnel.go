package vpngate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const stateDir = "/run/vpngate"

var ErrUnavailable = errors.New("no healthy VPN tunnel")

type slot struct {
	index int
	dev   string
	table string
	pref  string
}

func newSlot(i int) slot {
	return slot{i, "vg" + strconv.Itoa(i), strconv.Itoa(1100 + i), strconv.Itoa(1100 + i)}
}

func ipCmd(ctx context.Context, args ...string) error {
	b, err := exec.CommandContext(ctx, "ip", append([]string{"-4"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(b)))
	}
	return nil
}

func (s slot) installGuard(ctx context.Context) error {
	if err := ipCmd(ctx, "route", "replace", "unreachable", "default", "metric", "32767", "table", s.table); err != nil {
		return err
	}
	_ = ipCmd(ctx, "rule", "del", "pref", s.pref)
	return ipCmd(ctx, "rule", "add", "pref", s.pref, "oif", s.dev, "lookup", s.table)
}

type Tunnel struct {
	node      Node
	exit      netip.Addr
	slot      slot
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	dialer    *net.Dialer
	resolvers []*net.Resolver
	transport *http.Transport
	probe     *http.Client
	cancelReq atomic.Bool
}

// Prepare verifies that the process can install the tunnel routing guard.
func Prepare(ctx context.Context) error {
	if err := os.WriteFile(filepath.Join(stateDir, "vpn.auth"), []byte("vpn\nvpn\n"), 0600); err != nil {
		return err
	}
	return newSlot(0).installGuard(ctx)
}

func Start(ctx context.Context, index int, n Node) (*Tunnel, error) {
	s := newSlot(index)
	if err := s.installGuard(ctx); err != nil {
		return nil, err
	}
	return startTunnel(ctx, s, n)
}

func (t *Tunnel) ExitIP() netip.Addr       { return t.exit }
func (t *Tunnel) NodeIP() netip.Addr       { return t.node.IP() }
func (t *Tunnel) Context() context.Context { return t.ctx }
func (t *Tunnel) Cancel()                  { t.cancel() }

func (t *Tunnel) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(r)
}

func (t *Tunnel) CloseIdleConnections() { t.transport.CloseIdleConnections() }

func startTunnel(ctx context.Context, s slot, n Node) (*Tunnel, error) {
	runCtx, cancel := context.WithCancel(ctx)
	t := &Tunnel{node: n, slot: s, ctx: runCtx, cancel: cancel, done: make(chan struct{})}
	path := filepath.Join(stateDir, s.dev+".ovpn")
	if err := os.WriteFile(path, []byte(n.profile(s.dev, filepath.Join(stateDir, "vpn.auth"))), 0600); err != nil {
		cancel()
		return nil, err
	}
	cmd := exec.CommandContext(runCtx, "openvpn", "--config", path)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		cancel()
		os.Remove(path)
		return nil, err
	}
	go func() {
		if err := cmd.Wait(); err != nil && runCtx.Err() == nil {
			log.Printf("%s: OpenVPN stopped: %v", s.dev, err)
		}
		os.Remove(path)
		close(t.done)
	}()

	t.dialer = &net.Dialer{
		Timeout:   8 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   bindToTunnel(s.dev),
	}
	for _, dns := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		t.resolvers = append(t.resolvers, &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				if strings.HasPrefix(network, "udp") {
					network = "udp4"
				} else {
					network = "tcp4"
				}
				return t.dialer.DialContext(ctx, network, dns)
			},
		})
	}
	t.transport = &http.Transport{
		DialContext:       t.Dial,
		ForceAttemptHTTP2: true,
		MaxIdleConns:      128, MaxIdleConnsPerHost: 8,
		IdleConnTimeout: 60 * time.Second, TLSHandshakeTimeout: 8 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second, ExpectContinueTimeout: time.Second,
		DisableCompression: true,
	}
	t.probe = &http.Client{
		Transport: &http.Transport{
			DialContext: t.Dial, TLSHandshakeTimeout: 4 * time.Second,
			DisableKeepAlives: true, ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	readyCtx, stopWait := context.WithTimeout(ctx, 13*time.Second)
	defer stopWait()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-readyCtx.Done():
			t.Close()
			return nil, errors.New("timed out waiting for tunnel interface")
		case <-t.done:
			cancel()
			return nil, errors.New("OpenVPN exited before the tunnel was ready")
		case <-tick.C:
		}
		iface, err := net.InterfaceByName(s.dev)
		if err != nil || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		hasV4 := false
		for _, addr := range addrs {
			if p, err := netip.ParsePrefix(addr.String()); err == nil && p.Addr().Is4() {
				hasV4 = true
				break
			}
		}
		if err != nil || !hasV4 {
			continue
		}
		break
	}
	if err := ipCmd(readyCtx, "route", "replace", "default", "dev", s.dev, "metric", "10", "table", s.table); err != nil {
		t.Close()
		return nil, err
	}
	if err := ipCmd(readyCtx, "route", "get", "1.1.1.1", "oif", s.dev); err != nil {
		t.Close()
		return nil, err
	}
	t.exit = t.Check(ctx)
	if !t.exit.IsValid() {
		t.Close()
		return nil, errors.New("failed HTTPS exit check through the tunnel")
	}
	return t, nil
}

func (t *Tunnel) Close() {
	t.cancelReq.Store(true)
	t.transport.CloseIdleConnections()
	t.cancel()
	<-t.done
}

func (t *Tunnel) Alive() bool {
	select {
	case <-t.done:
		return false
	default:
		return !t.cancelReq.Load()
	}
}

func (t *Tunnel) Dial(ctx context.Context, _, address string) (net.Conn, error) {
	if !t.Alive() {
		return nil, errors.New("VPN tunnel is down")
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{a.Unmap()}
	} else {
		if len(host) > 254 || strings.ContainsAny(host, "%<>/\\ \t\r\n\x00") {
			return nil, errors.New("invalid destination name")
		}
		for _, r := range t.resolvers {
			resolveCtx, stopResolve := context.WithTimeout(ctx, 2*time.Second)
			found, err := r.LookupNetIP(resolveCtx, "ip4", strings.TrimSuffix(host, ".")+".")
			stopResolve()
			if err == nil {
				ips = found
				break
			}
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				break
			}
		}
	}
	var lastErr error
	for _, a := range ips {
		if !publicIPv4(a) {
			continue
		}
		attempt, stopDial := context.WithTimeout(ctx, 4*time.Second)
		c, err := t.dialer.DialContext(attempt, "tcp4", net.JoinHostPort(a.String(), port))
		stopDial()
		if err == nil {
			conn := &tunnelConn{TCPConn: c.(*net.TCPConn)}
			conn.stop = context.AfterFunc(t.ctx, func() { _ = conn.TCPConn.Close() })
			if !t.Alive() {
				conn.Close()
				return nil, ErrUnavailable
			}
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no public IPv4 destination found through tunnel DNS")
	}
	return nil, lastErr
}

type tunnelConn struct {
	*net.TCPConn
	stop func() bool
	once sync.Once
}

func (c *tunnelConn) Close() error {
	c.once.Do(func() { c.stop() })
	return c.TCPConn.Close()
}

func (t *Tunnel) Check(parent context.Context) netip.Addr {
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	const n = 2
	out := make(chan netip.Addr, n)
	for i, endpoint := range []string{"https://api.ipify.org/", "https://checkip.amazonaws.com/"} {
		go func() {
			if i > 0 {
				timer := time.NewTimer(700 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					out <- netip.Addr{}
					return
				}
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			var result netip.Addr
			if resp, err := t.probe.Do(req); err == nil {
				defer resp.Body.Close()
				if b, err := io.ReadAll(io.LimitReader(resp.Body, 128)); err == nil && resp.StatusCode == 200 {
					if a, err := netip.ParseAddr(strings.TrimSpace(string(b))); err == nil && publicIPv4(a) {
						result = a
					}
				}
			}
			out <- result
		}()
	}
	for range n {
		if a := <-out; a.IsValid() && t.Alive() {
			return a
		}
	}
	return netip.Addr{}
}
