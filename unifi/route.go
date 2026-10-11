package unifi

import (
	"context"
	"fmt"
	"net/http"
)

// StaticRoute is a static route (Settings → Routing → Static Routes): traffic
// for Network goes to NextHop, a router on one of the LANs.
type StaticRoute struct {
	ID       string `json:"_id,omitempty"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Network  string `json:"static-route_network"` // e.g. "192.168.2.0/24"
	NextHop  string `json:"static-route_nexthop"` // e.g. "192.168.1.4"
	Distance int    `json:"static-route_distance"`
	Kind     string `json:"static-route_type"` // "nexthop-route"
}

// ListRoutes returns the static routes.
func (c *Client) ListRoutes(ctx context.Context) ([]StaticRoute, error) {
	var out []StaticRoute
	if err := c.classicGet(ctx, "/rest/routing", &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []StaticRoute{}
	}
	return out, nil
}

// CreateRoute creates a static route to a next hop. The router checks the
// network form, routes to its own networks, duplicate networks and the
// distance, but accepts next hops it can't reach (or itself) and duplicate
// names: check with check.StaticRoute first.
func (c *Client) CreateRoute(ctx context.Context, r StaticRoute) (StaticRoute, error) {
	if r.Distance == 0 {
		r.Distance = 1
	}
	fields := map[string]any{"name": r.Name, "type": "static-route", "enabled": r.Enabled, "static-route_type": "nexthop-route",
		"static-route_network": r.Network, "static-route_nexthop": r.NextHop, "static-route_distance": r.Distance}
	return c.writeRoute(ctx, http.MethodPost, "/rest/routing", fields)
}

// UpdateRoute changes fields of a static route, e.g. {"enabled": false}.
func (c *Client) UpdateRoute(ctx context.Context, id string, fields map[string]any) (StaticRoute, error) {
	return c.writeRoute(ctx, http.MethodPut, "/rest/routing/"+id, fields)
}

// DeleteRoute deletes a static route. A route that doesn't exist gives an
// error satisfying IsNotFound.
func (c *Client) DeleteRoute(ctx context.Context, id string) error {
	var env classicEnvelope
	return c.write(ctx, http.MethodDelete, c.classic("/rest/routing/"+id), nil, &env)
}

func (c *Client) writeRoute(ctx context.Context, method, path string, fields map[string]any) (StaticRoute, error) {
	var env classicEnvelope
	if err := c.write(ctx, method, c.classic(path), fields, &env); err != nil {
		return StaticRoute{}, err
	}
	var out []StaticRoute
	if err := decodeClassic(method, path, env, &out); err != nil {
		return StaticRoute{}, err
	}
	if len(out) == 0 {
		return StaticRoute{}, fmt.Errorf("%s %s: empty response", method, path)
	}
	return out[0], nil
}
