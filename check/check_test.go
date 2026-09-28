package check_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/liketed/dreamrouter-go/check"
	"github.com/liketed/dreamrouter-go/unifi"
)

func ptr[T any](v T) *T { return &v }

func TestDNSRecord(t *testing.T) {
	ok := []unifi.DNSRecord{
		{RecordType: "a", Key: "nas.home.internal.", Value: " 192.168.1.50 "},
		{RecordType: "AAAA", Key: "nas.home.internal", Value: "FD00::50", TTL: 300},
		{RecordType: "CNAME", Key: "files.home.internal", Value: "nas.home.internal."},
		{RecordType: "MX", Key: "home.internal", Value: "mail.home.internal", Priority: 10},
		{RecordType: "NS", Key: "lab.home.internal", Value: "192.168.1.2"},
		{RecordType: "SRV", Key: "_sip._tcp.home.internal", Value: "pbx.home.internal", Priority: 10, Weight: 5, Port: 5060},
		{RecordType: "TXT", Key: "home.internal", Value: "v=spf1 -all"},
		{RecordType: "TXT", Key: "home.internal", Value: `"hello world"`},
	}
	for _, r := range ok {
		r := r
		if err := check.DNSRecord(&r); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	r := ok[0]
	_ = check.DNSRecord(&r)
	if r.RecordType != "A" || r.Key != "nas.home.internal" || r.Value != "192.168.1.50" {
		t.Errorf("not normalised: %+v", r)
	}
	r = ok[1]
	_ = check.DNSRecord(&r)
	if r.Value != "fd00::50" {
		t.Errorf("IPv6 not normalised: %q", r.Value)
	}

	bad := []struct {
		rec  unifi.DNSRecord
		want string
	}{
		{unifi.DNSRecord{RecordType: "A", Key: "x", Value: "999.1.1.1"}, `value must be an IPv4 address for A records (got "999.1.1.1")`},
		{unifi.DNSRecord{RecordType: "AAAA", Key: "x", Value: "192.168.1.5"}, "must be an IPv6 address"},
		{unifi.DNSRecord{RecordType: "MX", Key: "x", Value: "m", TTL: 60}, "ttl cannot be set for MX records (only A, AAAA, CNAME records)"},
		{unifi.DNSRecord{RecordType: "A", Key: "x", Value: "192.168.1.5", Port: 80}, "port cannot be set for A records (only SRV records)"},
		{unifi.DNSRecord{RecordType: "NS", Key: "x", Value: "ns1.home.internal"}, "conditional forwarders"},
		{unifi.DNSRecord{RecordType: "CNAME", Key: "x.home.internal", Value: "X.home.internal."}, "a CNAME cannot point to itself"},
		{unifi.DNSRecord{RecordType: "TXT", Key: "x", Value: `say "hi" now`}, "double quotes are only allowed around the whole value"},
		{unifi.DNSRecord{RecordType: "TXT", Key: "x", Value: strings.Repeat("x", 256)}, "at most 255 characters"},
		{unifi.DNSRecord{RecordType: "SRV", Key: "sip.home.internal", Value: "pbx"}, "_service._protocol.domain"},
		{unifi.DNSRecord{RecordType: "A", Key: "a,b", Value: "192.168.1.5"}, "must not be empty or contain whitespace or commas"},
		{unifi.DNSRecord{RecordType: "PTR", Key: "x", Value: "y"}, `unsupported record type "PTR"`},
		{unifi.DNSRecord{RecordType: "MX", Key: "x", Value: "m", Priority: 70000}, "priority must be between 0 and 65535"},
	}
	for _, tc := range bad {
		rec := tc.rec
		if err := check.DNSRecord(&rec); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: err = %v, want %q", tc.rec, err, tc.want)
		}
	}
}

func TestDNSProblemsSkipsUnknown(t *testing.T) {
	// Only the type is known: nothing else can be judged yet.
	if p := check.DNSProblems(check.DNSInput{Type: ptr("MX")}); len(p) != 0 {
		t.Fatalf("problems for unknown fields: %v", p)
	}
	// Several problems are reported at once, per field.
	p := check.DNSProblems(check.DNSInput{Type: ptr("MX"), Name: ptr("a b"), Value: ptr("m x"), TTL: ptr(int64(5)), Port: ptr(int64(1))})
	for _, f := range []string{"name", "value", "ttl", "port"} {
		if p[f] == "" {
			t.Errorf("no problem reported for %s: %v", f, p)
		}
	}
}

func TestMACAndIP(t *testing.T) {
	for in, want := range map[string]string{"AA-BB-CC-00-00-01": "aa:bb:cc:00:00:01", " aa:bb:cc:00:00:01 ": "aa:bb:cc:00:00:01", "aabb.cc00.0001": "aa:bb:cc:00:00:01"} {
		if got, err := check.MAC(in); err != nil || got != want {
			t.Errorf("MAC(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"zz:zz", "aa:bb:cc:00:00:01:02:03", ""} {
		if _, err := check.MAC(in); err == nil {
			t.Errorf("MAC(%q) accepted", in)
		}
	}
	if _, err := check.IPv4("fd00::1"); err == nil {
		t.Error("IPv4 accepted an IPv6 address")
	}
}

func TestNetworkFor(t *testing.T) {
	nets := []unifi.Network{
		{ID: "n1", Name: "Default", Subnet: "192.168.1.1/24"},
		{ID: "n2", Name: "IoT", Subnet: "10.0.20.1/24"},
		{ID: "wan", Name: "Internet 1"},
	}
	ip := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	if n, err := check.NetworkFor(nets, ip("10.0.20.7"), ""); err != nil || n.ID != "n2" {
		t.Errorf("by subnet: %v %v", n, err)
	}
	if n, err := check.NetworkFor(nets, ip("192.168.1.50"), "default"); err != nil || n.ID != "n1" {
		t.Errorf("by name: %v %v", n, err)
	}
	for addr, want := range map[string]string{
		"192.168.1.1":   "the router's own address",
		"192.168.1.0":   "network or broadcast address",
		"192.168.1.255": "network or broadcast address",
		"172.16.0.1":    "not in any network's subnet (networks: Default 192.168.1.1/24, IoT 10.0.20.1/24)",
	} {
		if _, err := check.NetworkFor(nets, ip(addr), ""); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", addr, err, want)
		}
	}
	if _, err := check.NetworkFor(nets, ip("192.168.1.50"), "IoT"); err == nil || !strings.Contains(err.Error(), `not in network "IoT"`) {
		t.Errorf("wrong network: %v", err)
	}
	if _, err := check.NetworkFor(nets, ip("192.168.1.50"), "Guest"); err == nil || !strings.Contains(err.Error(), `no network named "Guest"`) {
		t.Errorf("unknown network: %v", err)
	}
}
