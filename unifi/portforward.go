package unifi

import (
	"context"
	"fmt"
	"net/http"
)

// PortForward is a port forwarding rule (Settings → Routing → Port Forwarding).
//
// The router accepts several rules that don't work or conflict: the same
// port forwarded twice, reversed ranges, forwards to addresses outside the
// LANs or to the router itself, and WAN interfaces that don't exist. Check
// with check.PortForward first. Enabled is always sent: the router stores a
// rule without an enabled setting if it is left out.
type PortForward struct {
	ID          string `json:"_id,omitempty"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Interface   string `json:"pfwd_interface"` // "wan", "wan2" or "both"
	Source      string `json:"src"`            // "any", or an IPv4 address or CIDR allowed to connect
	Port        string `json:"dst_port"`       // port on the WAN: "8443", "40010-40020" or "80,443"
	ForwardIP   string `json:"fwd"`            // LAN address to forward to
	ForwardPort string `json:"fwd_port"`       // port on ForwardIP; only a single Port can differ, ranges and lists must match
	Protocol    string `json:"proto"`          // "tcp_udp", "tcp" or "udp"
	Log         bool   `json:"log"`
}

const pfPath = "/rest/portforward"

// ListPortForwards returns all port forwarding rules.
func (c *Client) ListPortForwards(ctx context.Context) ([]PortForward, error) {
	var out []PortForward
	if err := c.classicGet(ctx, pfPath, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []PortForward{}
	}
	return out, nil
}

// CreatePortForward creates a rule and returns it as stored.
func (c *Client) CreatePortForward(ctx context.Context, pf PortForward) (PortForward, error) {
	pf.ID = ""
	return c.writePortForward(ctx, http.MethodPost, pfPath, pf)
}

// UpdatePortForward replaces rule id with pf and returns it as stored.
func (c *Client) UpdatePortForward(ctx context.Context, id string, pf PortForward) (PortForward, error) {
	pf.ID = ""
	return c.writePortForward(ctx, http.MethodPut, pfPath+"/"+id, pf)
}

// DeletePortForward deletes a rule. A rule that doesn't exist gives an
// error satisfying IsNotFound.
func (c *Client) DeletePortForward(ctx context.Context, id string) error {
	var env classicEnvelope
	return c.write(ctx, http.MethodDelete, c.classic(pfPath+"/"+id), nil, &env)
}

func (c *Client) writePortForward(ctx context.Context, method, path string, pf PortForward) (PortForward, error) {
	var env classicEnvelope
	if err := c.write(ctx, method, c.classic(path), pf, &env); err != nil {
		return PortForward{}, err
	}
	var out []PortForward
	if err := decodeClassic(method, path, env, &out); err != nil {
		return PortForward{}, err
	}
	if len(out) == 0 {
		return PortForward{}, fmt.Errorf("%s %s: empty response", method, path)
	}
	return out[0], nil
}
