package check

import (
	"strings"
	"testing"
)

func TestDHCPOptions(t *testing.T) {
	for _, ok := range [][]string{nil, {"192.168.1.1"}, {"192.168.1.1", "1.1.1.1", "9.9.9.9", "8.8.8.8"}} {
		if err := DHCPDNS(ok); err != nil {
			t.Errorf("DHCPDNS(%v): %v", ok, err)
		}
	}
	for servers, want := range map[string]string{
		"not-an-ip":            "must be an IPv4 address",
		"dns.google":           "must be an IPv4 address",
		"1.1.1.1,8.8.8.8":      "must be an IPv4 address",
		"2606:4700:4700::1111": "must be an IPv4 address",
		"":                     "must be an IPv4 address",
		"1.1.1.1 1.1.1.1":      "listed twice",
		"1 2 3 4 5":            "at most 4 DNS servers",
	} {
		list := strings.Fields(servers)
		if servers == "" || strings.Contains(servers, ",") || !strings.Contains(servers, " ") {
			list = []string{servers}
		}
		if servers == "1 2 3 4 5" {
			list = []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5"}
		}
		if err := DHCPDNS(list); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("DHCPDNS(%q) = %v, want %q", list, err, want)
		}
	}
	if err := NTPServers([]string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}); err == nil || !strings.Contains(err.Error(), "at most 2 NTP servers") {
		t.Errorf("three NTP servers: %v", err)
	}
	if err := NTPServers([]string{"pool.ntp.org"}); err == nil {
		t.Error("NTP host name accepted")
	}
	for _, s := range []int{120, 86400, 31536000} {
		if err := LeaseTime(s); err != nil {
			t.Errorf("LeaseTime(%d): %v", s, err)
		}
	}
	for _, s := range []int{0, 1, 60, 119, 31536001} {
		if err := LeaseTime(s); err == nil {
			t.Errorf("LeaseTime(%d) accepted", s)
		}
	}
	for _, d := range []string{"home.internal", "localdomain", "a-b.c1"} {
		if err := DomainName(d); err != nil {
			t.Errorf("DomainName(%q): %v", d, err)
		}
	}
	for _, d := range []string{"", "home internal", "a,b", "-a.b", "a..b", "Home.Internal", "a_b"} {
		if err := DomainName(d); err == nil {
			t.Errorf("DomainName(%q) accepted", d)
		}
	}
}
