package unifi

import (
	"context"
	"fmt"
	"net/http"
)

// WiFi is a Wi-Fi network (SSID), attached to a network.
type WiFi struct {
	ID        string   `json:"_id,omitempty"`
	Name      string   `json:"name"` // the SSID
	Enabled   bool     `json:"enabled"`
	Hidden    bool     `json:"hide_ssid"`
	NetworkID string   `json:"networkconf_id"`
	Bands     []string `json:"wlan_bands,omitempty"` // "2g", "5g", "6g"
	Security  string   `json:"security,omitempty"`   // "wpapsk" (password) or "open"
	// Password is the WPA passphrase. It is sensitive: never print it.
	Password string `json:"x_passphrase,omitempty"`
}

// WiFiSpec describes a new Wi-Fi network secured with a password
// (WPA2/WPA3), broadcast by all access points.
type WiFiSpec struct {
	Name      string
	Password  string
	NetworkID string
	Bands     []string // default 2.4 and 5 GHz
	Hidden    bool
	Disabled  bool
}

// ListWiFi returns the Wi-Fi networks.
func (c *Client) ListWiFi(ctx context.Context) ([]WiFi, error) {
	var out []WiFi
	if err := c.classicGet(ctx, "/rest/wlanconf", &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []WiFi{}
	}
	return out, nil
}

// CreateWiFi creates a Wi-Fi network. While the access points apply it,
// Wi-Fi devices on every Wi-Fi network disconnect briefly (15–30 seconds
// on a Dream Router 7 with one access point). The router accepts duplicate
// names and invalid passphrases: check with check.NewWiFi first.
func (c *Client) CreateWiFi(ctx context.Context, spec WiFiSpec) (WiFi, error) {
	var groups []struct {
		ID     string `json:"_id"`
		Hidden string `json:"attr_hidden_id"`
	}
	if err := c.do(ctx, http.MethodGet, c.v2("/apgroups"), nil, &groups); err != nil {
		return WiFi{}, err
	}
	var users []struct {
		ID     string `json:"_id"`
		Hidden string `json:"attr_hidden_id"`
	}
	if err := c.classicGet(ctx, "/rest/usergroup", &users); err != nil {
		return WiFi{}, err
	}
	apGroup, userGroup := "", ""
	for _, g := range groups {
		if g.Hidden == "default" {
			apGroup = g.ID
		}
	}
	for _, u := range users {
		if u.Hidden == "Default" {
			userGroup = u.ID
		}
	}
	if apGroup == "" || userGroup == "" {
		return WiFi{}, fmt.Errorf("the router has no default access point group or user group")
	}
	bands := spec.Bands
	if len(bands) == 0 {
		bands = []string{"2g", "5g"}
	}
	fields := map[string]any{"name": spec.Name, "enabled": !spec.Disabled, "hide_ssid": spec.Hidden,
		"security": "wpapsk", "wpa_mode": "wpa2", "wpa_enc": "ccmp", "wpa3_support": true, "wpa3_transition": true,
		"pmf_mode": "optional", "x_passphrase": spec.Password, "networkconf_id": spec.NetworkID,
		"ap_group_ids": []string{apGroup}, "ap_group_mode": "all", "usergroup_id": userGroup, "wlan_bands": bands}
	return c.writeWiFi(ctx, http.MethodPost, "/rest/wlanconf", fields)
}

// UpdateWiFi changes fields of a Wi-Fi network, e.g. {"enabled": false},
// {"x_passphrase": "..."} or {"networkconf_id": "..."}. Like creating, it
// makes the access points re-apply their settings.
func (c *Client) UpdateWiFi(ctx context.Context, id string, fields map[string]any) (WiFi, error) {
	return c.writeWiFi(ctx, http.MethodPut, "/rest/wlanconf/"+id, fields)
}

// DeleteWiFi deletes a Wi-Fi network. A Wi-Fi network that doesn't exist
// gives an error satisfying IsNotFound.
func (c *Client) DeleteWiFi(ctx context.Context, id string) error {
	var env classicEnvelope
	return c.write(ctx, http.MethodDelete, c.classic("/rest/wlanconf/"+id), nil, &env)
}

func (c *Client) writeWiFi(ctx context.Context, method, path string, fields map[string]any) (WiFi, error) {
	var env classicEnvelope
	if err := c.write(ctx, method, c.classic(path), fields, &env); err != nil {
		return WiFi{}, err
	}
	var out []WiFi
	if err := decodeClassic(method, path, env, &out); err != nil {
		return WiFi{}, err
	}
	if len(out) == 0 {
		return WiFi{}, fmt.Errorf("%s %s: empty response", method, path)
	}
	return out[0], nil
}
