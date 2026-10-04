package check

import (
	"strings"
	"testing"

	"github.com/liketed/dreamrouter-go/unifi"
)

var existingNets = []unifi.Network{
	{ID: "lan", Name: "Default", Purpose: "corporate", Subnet: "192.168.1.1/24"},
	{ID: "wan", Name: "Internet 1", Purpose: "wan"},
	{ID: "iot", Name: "IoT", Purpose: "corporate", Subnet: "192.168.20.1/24", VLAN: 20, VLANEnabled: true},
}

func TestNewNetwork(t *testing.T) {
	spec := unifi.NetworkSpec{Name: " Kids ", VLAN: 30, Subnet: "192.168.30.1/24", DNS: []string{"94.140.14.15", "94.140.15.16"}}
	if err := NewNetwork(&spec, existingNets); err != nil {
		t.Fatal(err)
	}
	if spec.Name != "Kids" || spec.DHCPStart != "192.168.30.6" || spec.DHCPStop != "192.168.30.254" {
		t.Fatalf("defaults: %+v", spec)
	}
	small := unifi.NetworkSpec{Name: "s", VLAN: 40, Subnet: "10.9.9.1/29"}
	if err := NewNetwork(&small, existingNets); err != nil || small.DHCPStart != "10.9.9.6" || small.DHCPStop != "10.9.9.6" {
		t.Fatalf("a /29: %+v %v", small, err)
	}
	for _, tc := range []struct {
		spec unifi.NetworkSpec
		want string
	}{
		{unifi.NetworkSpec{Name: "", VLAN: 30, Subnet: "192.168.30.1/24"}, "needs a name"},
		{unifi.NetworkSpec{Name: "iot", VLAN: 30, Subnet: "192.168.30.1/24"}, `named "IoT" already exists`},
		{unifi.NetworkSpec{Name: "x", VLAN: 1, Subnet: "192.168.30.1/24"}, "from 2 to 4094"},
		{unifi.NetworkSpec{Name: "x", VLAN: 4095, Subnet: "192.168.30.1/24"}, "from 2 to 4094"},
		{unifi.NetworkSpec{Name: "x", VLAN: 20, Subnet: "192.168.30.1/24"}, `"IoT" already uses VLAN 20`},
		{unifi.NetworkSpec{Name: "x", VLAN: 30, Subnet: "192.168.30.0/24"}, "router's address on it, e.g. 192.168.30.1/24"},
		{unifi.NetworkSpec{Name: "x", VLAN: 30, Subnet: "nope"}, "router's address with a prefix"},
		{unifi.NetworkSpec{Name: "x", VLAN: 30, Subnet: "8.8.8.1/24"}, "not a private range"},
		{unifi.NetworkSpec{Name: "x", VLAN: 30, Subnet: "192.168.1.1/24"}, `overlaps network "Default"`},
		{unifi.NetworkSpec{Name: "x", VLAN: 30, Subnet: "192.168.0.1/16"}, "overlaps network"},
		{unifi.NetworkSpec{Name: "x", VLAN: 30, Subnet: "192.168.30.1/31"}, "too small"},
		{unifi.NetworkSpec{Name: "x", VLAN: 30, Subnet: "192.168.30.1/24", DHCPStart: "10.0.0.6", DHCPStop: "10.0.0.254"}, "must be inside 192.168.30.0/24"},
		{unifi.NetworkSpec{Name: "x", VLAN: 30, Subnet: "192.168.30.1/24", DHCPStart: "192.168.30.254", DHCPStop: "192.168.30.6"}, "reversed"},
		{unifi.NetworkSpec{Name: "x", VLAN: 30, Subnet: "192.168.30.1/24", DHCPStart: "192.168.30.1", DHCPStop: "192.168.30.20"}, "includes the router's address"},
		{unifi.NetworkSpec{Name: "x", VLAN: 30, Subnet: "192.168.30.1/24", DNS: []string{"dns.adguard.com"}}, "must be an IPv4 address"},
	} {
		spec := tc.spec
		if err := NewNetwork(&spec, existingNets); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("NewNetwork(%+v) = %v, want %q", tc.spec, err, tc.want)
		}
	}
}

func TestNewWiFi(t *testing.T) {
	existing := []unifi.WiFi{{Name: "home"}}
	spec := unifi.WiFiSpec{Name: "kids", Password: "correct horse battery", NetworkID: "lan"}
	if err := NewWiFi(&spec, existing, existingNets); err != nil || len(spec.Bands) != 2 {
		t.Fatalf("NewWiFi: %+v %v", spec, err)
	}
	for _, tc := range []struct {
		spec unifi.WiFiSpec
		want string
	}{
		{unifi.WiFiSpec{Name: "home", Password: "correct horse", NetworkID: "lan"}, `named "home" already exists`},
		{unifi.WiFiSpec{Name: "", Password: "correct horse", NetworkID: "lan"}, "1 to 32 bytes"},
		{unifi.WiFiSpec{Name: strings.Repeat("k", 33), Password: "correct horse", NetworkID: "lan"}, "1 to 32 bytes"},
		{unifi.WiFiSpec{Name: "k", Password: "short12", NetworkID: "lan"}, "8 to 63 characters"},
		{unifi.WiFiSpec{Name: "k", Password: strings.Repeat("z", 64), NetworkID: "lan"}, "8 to 63 characters (or 64 hex digits)"},
		{unifi.WiFiSpec{Name: "k", Password: "pässword-long", NetworkID: "lan"}, "printable ASCII"},
		{unifi.WiFiSpec{Name: "k", Password: "correct horse", NetworkID: "lan", Bands: []string{"60g"}}, `band "60g"`},
		{unifi.WiFiSpec{Name: "k", Password: "correct horse", NetworkID: "nope"}, `no network with ID "nope"`},
	} {
		spec := tc.spec
		if err := NewWiFi(&spec, existing, existingNets); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("NewWiFi(%q) = %v, want %q", tc.spec.Name, err, tc.want)
		}
	}
	if err := WiFiPassword(strings.Repeat("ab", 32)); err != nil {
		t.Errorf("64 hex digits: %v", err)
	}
}
