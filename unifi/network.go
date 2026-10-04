package unifi

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// VLANID is a network's VLAN ID. The router sends it as a number (or, in
// older versions, a string); 0 means no VLAN.
type VLANID int

func (v *VLANID) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*v = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("VLAN ID %s is not a number", b)
	}
	*v = VLANID(n)
	return nil
}

// NetworkSpec describes a new network: a VLAN with its own subnet and DHCP.
type NetworkSpec struct {
	Name      string
	VLAN      int      // 2–4094
	Subnet    string   // the router's address on it, with the prefix, e.g. "192.168.30.1/24"
	DHCPStart string   // e.g. "192.168.30.6"
	DHCPStop  string   // e.g. "192.168.30.254"
	DNS       []string // DNS servers handed out; none means the router itself
}

// CreateNetwork creates a network (Settings → Networks). The router checks
// overlapping subnets, VLANs in use and DHCP ranges itself, but accepts
// duplicate names and public subnets: check with check.NewNetwork first.
func (c *Client) CreateNetwork(ctx context.Context, spec NetworkSpec) (Network, error) {
	fields := map[string]any{"name": spec.Name, "purpose": "corporate", "networkgroup": "LAN", "is_nat": true,
		"vlan_enabled": true, "vlan": spec.VLAN, "ip_subnet": spec.Subnet,
		"dhcpd_enabled": true, "dhcpd_start": spec.DHCPStart, "dhcpd_stop": spec.DHCPStop}
	for k, v := range DNSFields(spec.DNS) {
		fields[k] = v
	}
	var env classicEnvelope
	if err := c.write(ctx, http.MethodPost, c.classic("/rest/networkconf"), fields, &env); err != nil {
		return Network{}, err
	}
	var out []Network
	if err := decodeClassic(http.MethodPost, "/rest/networkconf", env, &out); err != nil {
		return Network{}, err
	}
	if len(out) == 0 {
		return Network{}, fmt.Errorf("POST /rest/networkconf: empty response")
	}
	return out[0], nil
}

// DeleteNetwork deletes a network. A network that doesn't exist gives an
// error satisfying IsNotFound.
func (c *Client) DeleteNetwork(ctx context.Context, id string) error {
	var env classicEnvelope
	return c.write(ctx, http.MethodDelete, c.classic("/rest/networkconf/"+id), nil, &env)
}
