package check

import (
	"strings"
	"testing"

	"github.com/liketed/dreamrouter-go/unifi"
)

var pfNetworks = []unifi.Network{
	{ID: "lan", Name: "Default", Purpose: "corporate", Subnet: "192.168.1.1/24"},
	{ID: "wan", Name: "Internet 1", Purpose: "wan"},
}

func TestPortForward(t *testing.T) {
	existing := []unifi.PortForward{
		{ID: "a", Name: "Minecraft", Enabled: true, Interface: "wan", Port: "25565", ForwardIP: "192.168.1.50", Protocol: "tcp"},
		{ID: "b", Name: "games", Enabled: true, Interface: "wan", Port: "27000-27010", ForwardIP: "192.168.1.51", Protocol: "udp"},
		{ID: "c", Name: "old", Enabled: false, Interface: "wan", Port: "8080", ForwardIP: "192.168.1.52", Protocol: "tcp_udp"},
	}
	ok := func(pf unifi.PortForward) unifi.PortForward {
		t.Helper()
		if err := PortForward(&pf, pfNetworks, existing); err != nil {
			t.Fatalf("PortForward(%+v): %v", pf, err)
		}
		return pf
	}
	// Defaults and normal forms.
	pf := ok(unifi.PortForward{Name: " web ", Enabled: true, Port: "8443", ForwardIP: "192.168.1.20"})
	if pf.Name != "web" || pf.ForwardPort != "8443" || pf.Protocol != "tcp_udp" || pf.Source != "any" || pf.Interface != "wan" {
		t.Fatalf("defaults: %+v", pf)
	}
	pf = ok(unifi.PortForward{Name: "x", Enabled: true, Port: "80, 443", ForwardPort: "80 ,443", ForwardIP: "192.168.1.20",
		Protocol: "both", Source: "203.0.113.9/24"})
	if pf.Port != "80,443" || pf.ForwardPort != "80,443" || pf.Protocol != "tcp_udp" || pf.Source != "203.0.113.0/24" {
		t.Fatalf("normal forms: %+v", pf)
	}
	ok(unifi.PortForward{Name: "range", Enabled: true, Port: "40010-40020", ForwardPort: "40010-40020", ForwardIP: "192.168.1.20", Protocol: "tcp"})
	ok(unifi.PortForward{Name: "mixed", Enabled: true, Port: "41110,41120-41125", ForwardIP: "192.168.1.20", Protocol: "tcp"})
	ok(unifi.PortForward{Name: "ssh", Enabled: true, Port: "2222", ForwardPort: "22", ForwardIP: "192.168.1.20", Protocol: "tcp"})
	// No conflict: different protocol, a disabled rule, the same rule (update), or this rule disabled.
	ok(unifi.PortForward{Name: "mc-udp", Enabled: true, Port: "25565", ForwardIP: "192.168.1.50", Protocol: "udp"})
	ok(unifi.PortForward{Name: "new8080", Enabled: true, Port: "8080", ForwardIP: "192.168.1.20"})
	ok(unifi.PortForward{ID: "a", Name: "Minecraft", Enabled: true, Port: "25565", ForwardIP: "192.168.1.60", Protocol: "tcp"})
	ok(unifi.PortForward{Name: "spare", Enabled: false, Port: "25565", ForwardIP: "192.168.1.61", Protocol: "tcp"})

	for _, tc := range []struct {
		pf   unifi.PortForward
		want string
	}{
		{unifi.PortForward{Name: "", Port: "1", ForwardIP: "192.168.1.20"}, "needs a name"},
		{unifi.PortForward{Name: "minecraft", Port: "1", ForwardIP: "192.168.1.20"}, `named "Minecraft" already exists`},
		{unifi.PortForward{Name: "x", Port: "0", ForwardIP: "192.168.1.20"}, "outside 1–65535"},
		{unifi.PortForward{Name: "x", Port: "70000", ForwardIP: "192.168.1.20"}, "outside 1–65535"},
		{unifi.PortForward{Name: "x", Port: "abc", ForwardIP: "192.168.1.20"}, "is not a port"},
		{unifi.PortForward{Name: "x", Port: "80,", ForwardIP: "192.168.1.20"}, "is not a port"},
		{unifi.PortForward{Name: "x", Port: "40090-40080", ForwardIP: "192.168.1.20"}, "reversed; write it as 40080-40090"},
		{unifi.PortForward{Name: "x", Port: "40100-40110", ForwardPort: "40100-40105", ForwardIP: "192.168.1.20"}, "can only be forwarded to the same ports (40100-40110), not 40100-40105"},
		{unifi.PortForward{Name: "x", Port: "40010-40020", ForwardPort: "50010-50020", ForwardIP: "192.168.1.20"}, "can only be forwarded to the same ports"},
		{unifi.PortForward{Name: "x", Port: "41100,41101", ForwardPort: "51100,51101", ForwardIP: "192.168.1.20"}, "can only be forwarded to the same ports"},
		{unifi.PortForward{Name: "x", Port: "41070-41080", ForwardPort: "41070", ForwardIP: "192.168.1.20"}, "can only be forwarded to the same ports"},
		{unifi.PortForward{Name: "x", Port: "80", ForwardPort: "8000-8001", ForwardIP: "192.168.1.20"}, "can only be forwarded to the same ports"},
		{unifi.PortForward{Name: "x", Port: "1", ForwardIP: "nas.local"}, "forward address: invalid IPv4"},
		{unifi.PortForward{Name: "x", Port: "1", ForwardIP: "8.8.8.8"}, "forward address:"},
		{unifi.PortForward{Name: "x", Port: "1", ForwardIP: "192.168.1.1"}, "router's own address"},
		{unifi.PortForward{Name: "x", Port: "1", ForwardIP: "192.168.1.20", Protocol: "icmp"}, "must be tcp, udp or both"},
		{unifi.PortForward{Name: "x", Port: "1", ForwardIP: "192.168.1.20", Source: "nope"}, `source "nope"`},
		{unifi.PortForward{Name: "x", Port: "1", ForwardIP: "192.168.1.20", Interface: "wan9"}, "must be wan, wan2 or both"},
		{unifi.PortForward{Name: "x", Port: "1", ForwardIP: "192.168.1.20", Interface: "wan2"}, "needs a second internet connection, and the router has 1"},
		{unifi.PortForward{Name: "x", Enabled: true, Port: "25560-25570", ForwardIP: "192.168.1.20", Protocol: "tcp"}, `TCP 25560-25570 is already forwarded by "Minecraft"`},
		{unifi.PortForward{Name: "x", Enabled: true, Port: "27005", ForwardIP: "192.168.1.20"}, `already forwarded by "games"`},
	} {
		pf := tc.pf
		err := PortForward(&pf, pfNetworks, existing)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("PortForward(%+v) = %v, want %q", tc.pf, err, tc.want)
		}
	}
	// A second WAN allows wan2 and both.
	two := append([]unifi.Network{{ID: "wan2", Name: "Internet 2", Purpose: "wan"}}, pfNetworks...)
	pf = unifi.PortForward{Name: "x", Port: "1", ForwardIP: "192.168.1.20", Interface: "both"}
	if err := PortForward(&pf, two, nil); err != nil {
		t.Fatal(err)
	}
}
