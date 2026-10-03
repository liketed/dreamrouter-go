package unifi

import (
	"context"
	"fmt"
	"net/http"
)

// SSHSettings are the router's two SSH settings.
type SSHSettings struct {
	// Router is SSH to the router itself (UniFi OS: Control Plane → Console → SSH).
	Router bool
	// Devices is SSH to adopted UniFi devices such as access points, with a
	// shared username and password (Network: Device SSH Authentication).
	Devices         bool
	DevicesUsername string
	// DevicesPasswordAuth is whether devices accept that password (rather
	// than SSH keys only).
	DevicesPasswordAuth bool
}

type mgmtSetting struct {
	ID          string `json:"_id"`
	SSHEnabled  bool   `json:"x_ssh_enabled"`
	SSHUsername string `json:"x_ssh_username"`
	SSHPassAuth bool   `json:"x_ssh_auth_password_enabled"`
}

func (c *Client) mgmt(ctx context.Context) (mgmtSetting, error) {
	var settings []struct {
		Key string `json:"key"`
		mgmtSetting
	}
	if err := c.classicGet(ctx, "/rest/setting", &settings); err != nil {
		return mgmtSetting{}, err
	}
	for _, s := range settings {
		if s.Key == "mgmt" {
			return s.mgmtSetting, nil
		}
	}
	return mgmtSetting{}, fmt.Errorf("the router has no mgmt setting")
}

// GetSSH returns both SSH settings.
func (c *Client) GetSSH(ctx context.Context) (SSHSettings, error) {
	var sys struct {
		SSH bool `json:"ssh"`
	}
	if err := c.do(ctx, http.MethodGet, c.base+"/api/system", nil, &sys); err != nil {
		return SSHSettings{}, err
	}
	m, err := c.mgmt(ctx)
	if err != nil {
		return SSHSettings{}, err
	}
	return SSHSettings{Router: sys.SSH, Devices: m.SSHEnabled, DevicesUsername: m.SSHUsername, DevicesPasswordAuth: m.SSHPassAuth}, nil
}

// SetRouterSSH turns SSH to the router itself on or off. Turning it on keeps
// the root password that was set before.
func (c *Client) SetRouterSSH(ctx context.Context, enabled bool) error {
	return c.write(ctx, http.MethodPatch, c.base+"/api/system", map[string]any{"ssh": map[string]any{"enabled": enabled}}, nil)
}

// SetDevicesSSH turns SSH to adopted devices on or off. It writes nothing if
// the setting is already as asked: every write of this setting makes the
// router issue its devices a new internal API token.
func (c *Client) SetDevicesSSH(ctx context.Context, enabled bool) error {
	m, err := c.mgmt(ctx)
	if err != nil {
		return err
	}
	if m.SSHEnabled == enabled {
		return nil
	}
	var env classicEnvelope
	return c.write(ctx, http.MethodPut, c.classic("/rest/setting/mgmt/"+m.ID), map[string]any{"x_ssh_enabled": enabled}, &env)
}
