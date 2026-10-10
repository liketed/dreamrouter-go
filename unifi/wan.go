package unifi

import (
	"context"
	"fmt"
	"net/http"
	"sort"
)

// WAN is an internet connection (Settings → Internet), e.g. "Internet 1".
// The router stores it like a network with purpose "wan".
type WAN struct {
	ID           string `json:"_id"`
	Name         string `json:"name"`
	NetworkGroup string `json:"wan_networkgroup"` // "WAN" (Internet 1), "WAN2" (Internet 2)
	Type         string `json:"wan_type"`         // "pppoe", "dhcp" or "static"
	Username     string `json:"wan_username"`     // PPPoE
	// Password is the PPPoE password. It is sensitive: never print it.
	Password      string `json:"x_wan_password"`
	VLANEnabled   bool   `json:"wan_vlan_enabled"`
	VLAN          VLANID `json:"wan_vlan"`
	DNSPreference string `json:"wan_dns_preference"` // "auto" (from the provider) or "manual"
	DNS1          string `json:"wan_dns1"`
	DNS2          string `json:"wan_dns2"`
	// Static connections.
	IP      string `json:"wan_ip"`
	Netmask string `json:"wan_netmask"`
	Gateway string `json:"wan_gateway"`
	// FailoverPriority 1 is the primary connection; LoadBalanceType is e.g.
	// "weighted" or "failover-only".
	FailoverPriority int    `json:"wan_failover_priority"`
	LoadBalanceType  string `json:"wan_load_balance_type"`
}

// ListWANs returns the internet connections, primary first.
func (c *Client) ListWANs(ctx context.Context) ([]WAN, error) {
	var all []struct {
		Purpose string `json:"purpose"`
		WAN
	}
	if err := c.classicGet(ctx, "/rest/networkconf", &all); err != nil {
		return nil, err
	}
	var out []WAN
	for _, n := range all {
		if n.Purpose == "wan" {
			out = append(out, n.WAN)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].NetworkGroup < out[j].NetworkGroup })
	return out, nil
}

// UpdateWAN changes fields of an internet connection, e.g.
// {"wan_type": "pppoe", "wan_username": "...", "x_wan_password": "...",
// "wan_vlan_enabled": true, "wan_vlan": 10}. A connection whose settings
// change reconnects, so it is briefly down. The router checks these fields
// itself (PPPoE credentials, VLAN 1–4094, a gateway for static, DNS servers).
func (c *Client) UpdateWAN(ctx context.Context, id string, fields map[string]any) (WAN, error) {
	var env classicEnvelope
	path := "/rest/networkconf/" + id
	if err := c.write(ctx, http.MethodPut, c.classic(path), fields, &env); err != nil {
		return WAN{}, err
	}
	var out []WAN
	if err := decodeClassic(http.MethodPut, path, env, &out); err != nil {
		return WAN{}, err
	}
	if len(out) == 0 {
		return WAN{}, fmt.Errorf("PUT %s: empty response", path)
	}
	return out[0], nil
}

// Port is one of the router's own ports and the role it has.
type Port struct {
	Index     int    // as numbered in the web UI: 1 = "Port 1"
	Name      string // e.g. "Port 3", "SFP+ 1"
	Interface string // e.g. "eth2"
	Media     string // e.g. "2.5GE", "SFP+"
	Up        bool
	SpeedMbps int
	Role      string // "LAN", "WAN" (Internet 1) or "WAN2" (Internet 2)
}

// WANLink is the live state of an internet connection's port.
type WANLink struct {
	NetworkGroup string // "WAN" or "WAN2"
	Interface    string
	Up           bool
	IP           string
}

type rawGateway struct {
	ID        string `json:"_id"`
	Type      string `json:"type"`
	Overrides []struct {
		Interface    string `json:"ifname"`
		NetworkGroup string `json:"networkgroup"`
	} `json:"ethernet_overrides"`
	Ports []struct {
		Index int     `json:"port_idx"`
		Name  string  `json:"name"`
		Iface string  `json:"ifname"`
		Media string  `json:"media"`
		Up    bool    `json:"up"`
		Speed flexNum `json:"speed"`
	} `json:"port_table"`
	WAN1 rawWANLink `json:"wan1"`
	WAN2 rawWANLink `json:"wan2"`
}

type rawWANLink struct {
	Iface string `json:"ifname"`
	Name  string `json:"name"`
	Up    bool   `json:"up"`
	IP    string `json:"ip"`
}

func (c *Client) gateway(ctx context.Context) (rawGateway, error) {
	var devices []rawGateway
	if err := c.classicGet(ctx, "/stat/device", &devices); err != nil {
		return rawGateway{}, err
	}
	for _, d := range devices {
		switch d.Type {
		case "udm", "ugw", "uxg":
			return d, nil
		}
	}
	return rawGateway{}, fmt.Errorf("the router isn't listed among its devices")
}

// Ports returns the router's ports with their roles, and the live state of
// each internet connection's port.
func (c *Client) Ports(ctx context.Context) ([]Port, []WANLink, error) {
	g, err := c.gateway(ctx)
	if err != nil {
		return nil, nil, err
	}
	role := map[string]string{}
	for _, o := range g.Overrides {
		role[o.Interface] = o.NetworkGroup
	}
	var ports []Port
	for _, p := range g.Ports {
		r := role[p.Iface]
		if r == "" {
			r = "LAN"
		}
		ports = append(ports, Port{Index: p.Index, Name: p.Name, Interface: p.Iface, Media: p.Media, Up: p.Up, SpeedMbps: int(p.Speed), Role: r})
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Index < ports[j].Index })
	var links []WANLink
	for group, l := range map[string]rawWANLink{"WAN": g.WAN1, "WAN2": g.WAN2} {
		iface := l.Iface
		if iface == "" {
			iface = l.Name
		}
		if iface != "" {
			links = append(links, WANLink{NetworkGroup: group, Interface: iface, Up: l.Up, IP: l.IP})
		}
	}
	sort.Slice(links, func(i, j int) bool { return links[i].NetworkGroup < links[j].NetworkGroup })
	return ports, links, nil
}

// SetPortRoles sets which port each internet connection uses; roles maps
// interfaces (e.g. "eth2") to "LAN", "WAN" or "WAN2", and must cover every
// port. The router reconfigures its ports, which can briefly interrupt
// traffic; a port that becomes a WAN port stops serving the LAN.
func (c *Client) SetPortRoles(ctx context.Context, roles map[string]string) error {
	g, err := c.gateway(ctx)
	if err != nil {
		return err
	}
	var ifaces []string
	for i := range roles {
		ifaces = append(ifaces, i)
	}
	sort.Strings(ifaces)
	overrides := make([]map[string]string, 0, len(roles))
	for _, i := range ifaces {
		overrides = append(overrides, map[string]string{"ifname": i, "networkgroup": roles[i]})
	}
	var env classicEnvelope
	return c.write(ctx, http.MethodPut, c.classic("/rest/device/"+g.ID), map[string]any{"ethernet_overrides": overrides}, &env)
}
