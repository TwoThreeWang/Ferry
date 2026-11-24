package vpngate

import (
	"encoding/base64"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestCatalogueBuildsSafeConfig(t *testing.T) {
	profile := []byte("dev tun\r\nproto udp\r\nremote 8.8.8.8 1194\r\nscript-security 3\r\nup /remote.sh\r\nredirect-gateway\r\n<ca>\r\nPEM\r\n</ca>\r\n")
	input := "*vpn_servers\r\n" +
		"x,8.8.8.8,40000,15,10000000,Japan,JP,8,0,0,0,0,,," + base64.StdEncoding.EncodeToString(profile) +
		"\r\n*\r\n"
	nodes, err := parseCatalog(strings.NewReader(input), map[string]bool{"JP": true})
	if err != nil || len(nodes) != 1 {
		t.Fatalf("catalog: %d nodes, %v", len(nodes), err)
	}
	conf := nodes[0].profile("vg0", "/run/vpngate/vpn.auth")
	for _, want := range []string{"dev vg0", "remote 8.8.8.8 1194", "proto udp4", "route-nopull", "<ca>\nPEM\n</ca>"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, ban := range []string{"script-security 3", "up /remote.sh", "redirect-gateway"} {
		if strings.Contains(conf, ban) {
			t.Errorf("untrusted directive copied: %s", ban)
		}
	}
	if _, err := parseCatalog(strings.NewReader(strings.TrimSuffix(input, "*\r\n")), nil); err == nil {
		t.Fatal("accepted a truncated catalogue")
	}
}

func TestPublicOnly(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "169.254.169.254", "172.18.0.1", "10.0.0.1", "100.64.0.1", "192.168.1.1", "0.2.3.4", "224.0.0.1", "2001:db8::1"} {
		if publicIPv4(netip.MustParseAddr(value)) {
			t.Errorf("allowed %s", value)
		}
	}
	if !publicIPv4(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("blocked public address")
	}
}

func TestLiveCatalogue(t *testing.T) {
	path := os.Getenv("VPNGATE_TEST_CSV")
	if path == "" {
		t.Skip("set VPNGATE_TEST_CSV to test a real catalogue snapshot")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	nodes, err := parseCatalog(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("accepted %d nodes from the official VPNGate catalogue", len(nodes))
}
