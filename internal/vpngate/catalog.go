package vpngate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const catalogURL = "https://www.vpngate.net/api/iphone/"

var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
}

func publicIPv4(addr netip.Addr) bool {
	if !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

type Node struct {
	ip      netip.Addr
	port    uint16
	proto   string
	country string
	pem     map[string]string
	rank    float64
}

func (n Node) ID() string       { return netip.AddrPortFrom(n.ip, n.port).String() + "/" + n.proto }
func (n Node) IP() netip.Addr   { return n.ip }
func (n Node) Country() string  { return n.country }
func (n Node) Protocol() string { return n.proto }

// Only copy a numeric endpoint and known inline certificate blocks from the
// catalogue. Remote profiles cannot set scripts, files, proxy or routing options.
func parseProfile(raw []byte, n *Node) error {
	if len(raw) > 64<<10 {
		return errors.New("profile too large")
	}
	n.pem = make(map[string]string)
	var tag string
	var block strings.Builder
	scan := bufio.NewScanner(bytes.NewReader(raw))
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if tag != "" {
			if line == "</"+tag+">" {
				n.pem[tag] = block.String()
				tag = ""
				block.Reset()
			} else {
				if strings.ContainsAny(line, "<>\x00") {
					return errors.New("invalid inline block")
				}
				block.WriteString(line + "\n")
			}
			continue
		}
		switch line {
		case "<ca>", "<cert>", "<key>", "<tls-auth>", "<tls-crypt>":
			tag = line[1 : len(line)-1]
			if _, present := n.pem[tag]; present {
				return errors.New("duplicate inline block")
			}
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[0] == "proto" {
			switch parts[1] {
			case "tcp", "tcp-client", "tcp4", "tcp4-client":
				n.proto = "tcp4-client"
			case "udp", "udp4":
				n.proto = "udp4"
			}
		}
		if len(parts) == 3 && parts[0] == "remote" && parts[1] == n.ip.String() {
			p, err := strconv.ParseUint(parts[2], 10, 16)
			if err == nil && p != 0 {
				n.port = uint16(p)
			}
		}
	}
	if scan.Err() != nil || tag != "" || n.proto == "" || n.port == 0 || n.pem["ca"] == "" ||
		(n.pem["cert"] == "") != (n.pem["key"] == "") {
		return errors.New("unsupported VPNGate profile")
	}
	return nil
}

func (n Node) profile(dev, auth string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `client
dev %s
dev-type tun
proto %s
remote %s %d
nobind
disable-dco
remote-cert-tls server
data-ciphers AES-128-CBC:AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-128-CBC
auth SHA1
auth-user-pass %s
auth-nocache
allow-compression no
route-nopull
route-noexec
pull-filter accept "ifconfig "
pull-filter accept "topology "
pull-filter accept "peer-id "
pull-filter accept "cipher "
pull-filter accept "protocol-flags "
pull-filter ignore ""
connect-retry-max 1
connect-timeout 8
ping 10
ping-exit 25
remap-usr1 SIGTERM
verb 2
`, dev, n.proto, n.ip, n.port, auth)
	for _, k := range []string{"ca", "cert", "key", "tls-auth", "tls-crypt"} {
		if n.pem[k] != "" {
			fmt.Fprintf(&b, "<%s>\n%s</%s>\n", k, n.pem[k], k)
		}
	}
	if n.pem["tls-auth"] != "" {
		b.WriteString("key-direction 1\n")
	}
	return b.String()
}

func parseCatalog(r io.Reader, countries map[string]bool) ([]Node, error) {
	const limit = 12 << 20
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(body)
	if len(body) > limit || !bytes.HasPrefix(trimmed, []byte("*vpn_servers")) ||
		!bytes.HasSuffix(trimmed, []byte("\n*")) {
		return nil, errors.New("invalid or incomplete VPNGate catalogue")
	}
	c := csv.NewReader(bytes.NewReader(body))
	c.FieldsPerRecord = -1
	var nodes []Node
	for {
		row, err := c.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(row) != 15 || len(countries) != 0 && !countries[row[6]] {
			continue
		}
		ip, err := netip.ParseAddr(row[1])
		if err != nil || !publicIPv4(ip) {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(row[14])
		if err != nil {
			continue
		}
		n := Node{ip: ip, country: row[6]}
		if parseProfile(raw, &n) != nil {
			continue
		}
		num := func(s string) float64 {
			v, _ := strconv.ParseUint(s, 10, 63)
			return float64(v)
		}
		ping := num(row[3])
		if ping == 0 {
			ping = 500
		}
		n.rank = 14*math.Log1p(num(row[4])/1e6) + 3*math.Log1p(num(row[2])/1e4) -
			12*math.Log1p(ping/30) - 4*math.Log1p(num(row[7])/10)
		if n.proto == "udp4" {
			n.rank += 5
		}
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 {
		return nil, errors.New("no supported VPNGate nodes for the configured countries")
	}
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].rank > nodes[j].rank })
	return nodes, nil
}

type Catalogue struct {
	nodes   []Node
	refresh time.Time
	client  *http.Client
	filter  map[string]bool
}

// Refresh fetches a fresh node list, bypassing the catalogue cache.
func (c *Catalogue) Refresh(ctx context.Context) ([]Node, error) {
	c.refresh = time.Time{}
	c.nodes = nil
	return c.get(ctx)
}

func (c *Catalogue) get(ctx context.Context) ([]Node, error) {
	if time.Now().Before(c.refresh) && len(c.nodes) != 0 {
		return c.nodes, nil
	}
	get := func() ([]Node, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", catalogURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("catalogue status %d", resp.StatusCode)
		}
		return parseCatalog(resp.Body, c.filter)
	}
	nodes, err := get()
	if err != nil && len(c.nodes) != 0 {
		c.refresh = time.Now().Add(30 * time.Second)
		return c.nodes, nil
	}
	if err != nil {
		return nil, err
	}
	c.nodes, c.refresh = nodes, time.Now().Add(5*time.Minute)
	return c.nodes, nil
}

func NewCatalogue(filter map[string]bool) *Catalogue {
	return &Catalogue{
		filter: filter,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext:       (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
				ForceAttemptHTTP2: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}
