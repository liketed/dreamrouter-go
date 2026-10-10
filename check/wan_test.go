package check

import (
	"strings"
	"testing"

	"github.com/liketed/dreamrouter-go/unifi"
)

func TestWAN(t *testing.T) {
	for _, ok := range []unifi.WAN{
		{Type: "pppoe", Username: "eir@eir.ie", Password: "broadband1", VLANEnabled: true, VLAN: 10},
		{Type: "dhcp"},
		{Type: "dhcp", VLANEnabled: true, VLAN: 1},
		{Type: "static", IP: "203.0.113.10", Netmask: "255.255.255.0", Gateway: "203.0.113.1"},
		{Type: "dhcp", DNSPreference: "manual", DNS1: "1.1.1.1", DNS2: "9.9.9.9"},
	} {
		w := ok
		if err := WAN(&w); err != nil {
			t.Errorf("WAN(%+v): %v", ok, err)
		}
	}
	for _, tc := range []struct {
		w    unifi.WAN
		want string
	}{
		{unifi.WAN{Type: "pppoe", Username: "eir@eir.ie"}, "needs a username and a password"},
		{unifi.WAN{Type: "bogus"}, "must be pppoe, dhcp or static"},
		{unifi.WAN{Type: "dhcp", VLANEnabled: true, VLAN: 0}, "from 1 to 4094"},
		{unifi.WAN{Type: "dhcp", VLANEnabled: true, VLAN: 4095}, "from 1 to 4094"},
		{unifi.WAN{Type: "static", IP: "nope", Netmask: "255.255.255.0", Gateway: "203.0.113.1"}, "static address"},
		{unifi.WAN{Type: "static", IP: "203.0.113.10", Netmask: "255.0.255.0", Gateway: "203.0.113.1"}, "not a valid netmask"},
		{unifi.WAN{Type: "static", IP: "203.0.113.10", Netmask: "255.255.255.0", Gateway: "198.51.100.1"}, "must be another address in 203.0.113.0/24"},
		{unifi.WAN{Type: "dhcp", DNSPreference: "manual"}, "at least one server"},
		{unifi.WAN{Type: "dhcp", DNSPreference: "manual", DNS1: "dns.google"}, "must be an IPv4 address"},
	} {
		w := tc.w
		if err := WAN(&w); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("WAN(%+v) = %v, want %q", tc.w, err, tc.want)
		}
	}
}
