package check

import (
	"strings"
	"testing"

	"github.com/liketed/dreamrouter-go/unifi"
)

func TestStaticRoute(t *testing.T) {
	nets := []unifi.Network{{ID: "lan", Name: "Default", Purpose: "corporate", Subnet: "192.168.1.1/24"}, {ID: "wan", Name: "Internet 1", Purpose: "wan"}}
	others := []unifi.StaticRoute{{ID: "a", Name: "lab", Network: "10.10.0.0/16", NextHop: "192.168.1.20"}}
	r := unifi.StaticRoute{Name: " cudy ", Network: "192.168.2.0/24", NextHop: "192.168.1.4"}
	if err := StaticRoute(&r, nets, others); err != nil || r.Name != "cudy" || r.Distance != 1 {
		t.Fatalf("StaticRoute: %+v %v", r, err)
	}
	same := unifi.StaticRoute{ID: "a", Name: "lab", Network: "10.10.0.0/16", NextHop: "192.168.1.21"}
	if err := StaticRoute(&same, nets, others); err != nil {
		t.Fatalf("updating a route against itself: %v", err)
	}
	for _, tc := range []struct {
		r    unifi.StaticRoute
		want string
	}{
		{unifi.StaticRoute{Name: "", Network: "192.168.2.0/24", NextHop: "192.168.1.4"}, "needs a name"},
		{unifi.StaticRoute{Name: "LAB", Network: "192.168.2.0/24", NextHop: "192.168.1.4"}, `named "lab" already exists`},
		{unifi.StaticRoute{Name: "x", Network: "10.10.0.0/16", NextHop: "192.168.1.4"}, `"lab" already covers 10.10.0.0/16`},
		{unifi.StaticRoute{Name: "x", Network: "192.168.2.5/24", NextHop: "192.168.1.4"}, "should be written 192.168.2.0/24"},
		{unifi.StaticRoute{Name: "x", Network: "nope", NextHop: "192.168.1.4"}, "must be a network"},
		{unifi.StaticRoute{Name: "x", Network: "0.0.0.0/0", NextHop: "192.168.1.4"}, "default route"},
		{unifi.StaticRoute{Name: "x", Network: "192.168.1.0/25", NextHop: "192.168.1.4"}, `overlaps the router's own network "Default"`},
		{unifi.StaticRoute{Name: "x", Network: "192.168.2.0/24", NextHop: "8.8.8.8"}, "must be a router on one of your networks"},
		{unifi.StaticRoute{Name: "x", Network: "192.168.2.0/24", NextHop: "192.168.1.1"}, "router's own address"},
		{unifi.StaticRoute{Name: "x", Network: "192.168.2.0/24", NextHop: "nope"}, "next hop: invalid IPv4"},
		{unifi.StaticRoute{Name: "x", Network: "192.168.2.0/24", NextHop: "192.168.1.4", Distance: 256}, "from 1 to 255"},
	} {
		rt := tc.r
		if err := StaticRoute(&rt, nets, others); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("StaticRoute(%+v) = %v, want %q", tc.r, err, tc.want)
		}
	}
}
