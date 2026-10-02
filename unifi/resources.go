package unifi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DNSRecord is a static DNS record (Settings → Routing → DNS). Numeric fields
// a record type doesn't use are 0; a TTL of 0 means automatic.
type DNSRecord struct {
	ID         string `json:"_id,omitempty"`
	RecordType string `json:"record_type"`
	Key        string `json:"key"`
	Value      string `json:"value"`
	Enabled    bool   `json:"enabled"`
	TTL        int64  `json:"ttl"`
	Priority   int64  `json:"priority"`
	Weight     int64  `json:"weight"`
	Port       int64  `json:"port"`
}

// ListDNS returns all static DNS records.
func (c *Client) ListDNS(ctx context.Context) ([]DNSRecord, error) {
	return cachedList(c, ctx, &c.dnsCache, &c.dnsTime, func() ([]DNSRecord, error) {
		var out []DNSRecord
		err := c.do(ctx, http.MethodGet, c.v2("/static-dns"), nil, &out)
		return out, err
	})
}

// GetDNS returns the record with the given ID, or an error satisfying
// IsNotFound. (The router has no call for a single record, so this lists them.)
func (c *Client) GetDNS(ctx context.Context, id string) (DNSRecord, error) {
	records, err := c.ListDNS(ctx)
	if err != nil {
		return DNSRecord{}, err
	}
	for _, r := range records {
		if r.ID == id {
			return r, nil
		}
	}
	return DNSRecord{}, notFound("static-dns/" + id)
}

// CreateDNS adds a record and returns it as stored, including its ID.
func (c *Client) CreateDNS(ctx context.Context, r DNSRecord) (DNSRecord, error) {
	r.ID = ""
	var out DNSRecord
	err := c.write(ctx, http.MethodPost, c.v2("/static-dns"), r, &out)
	return out, err
}

// UpdateDNS replaces the record with r.ID and returns it as stored.
func (c *Client) UpdateDNS(ctx context.Context, r DNSRecord) (DNSRecord, error) {
	if r.ID == "" {
		return DNSRecord{}, fmt.Errorf("update: record has no ID")
	}
	var out DNSRecord
	err := c.write(ctx, http.MethodPut, c.v2("/static-dns/"+r.ID), r, &out)
	return out, err
}

// DeleteDNS removes the record with the given ID.
func (c *Client) DeleteDNS(ctx context.Context, id string) error {
	return c.write(ctx, http.MethodDelete, c.v2("/static-dns/"+id), nil, nil)
}

// Network is a network from Settings → Networks.
type Network struct {
	ID          string `json:"_id"`
	Name        string `json:"name"`
	Purpose     string `json:"purpose"`   // e.g. "corporate", "guest", "wan"
	Subnet      string `json:"ip_subnet"` // gateway address with prefix, e.g. 192.168.1.1/24
	VLAN        string `json:"vlan,omitempty"`
	DHCPEnabled bool   `json:"dhcpd_enabled"`
	DHCPStart   string `json:"dhcpd_start"`
	DHCPStop    string `json:"dhcpd_stop"`
	DomainName  string `json:"domain_name"`

	// Network boot (PXE). The router serves these as dnsmasq
	// "dhcp-boot=...,FILE,,SERVER" while BootEnabled is set. It won't accept
	// an empty BootFilename once one has been stored, so turning network boot
	// off keeps the server and file.
	BootEnabled  bool   `json:"dhcpd_boot_enabled"`
	BootServer   string `json:"dhcpd_boot_server"`
	BootFilename string `json:"dhcpd_boot_filename"`
	// TFTPServer is DHCP option 66. It is handed out whenever it is set,
	// independently of BootEnabled.
	TFTPServer string `json:"dhcpd_tftp_server"`
}

// ListNetworks returns the configured networks.
func (c *Client) ListNetworks(ctx context.Context) ([]Network, error) {
	var env classicEnvelope
	if err := c.do(ctx, http.MethodGet, c.classic("/rest/networkconf"), nil, &env); err != nil {
		return nil, err
	}
	var out []Network
	err := decodeClassic(http.MethodGet, "/rest/networkconf", env, &out)
	return out, err
}

// UpdateNetwork changes the given fields of a network (API names, e.g.
// "dhcpd_boot_enabled") and returns it as stored. Only the fields given are
// changed.
func (c *Client) UpdateNetwork(ctx context.Context, id string, fields map[string]any) (Network, error) {
	var env classicEnvelope
	path := "/rest/networkconf/" + id
	if err := c.write(ctx, http.MethodPut, c.classic(path), fields, &env); err != nil {
		return Network{}, err
	}
	var out []Network
	if err := decodeClassic(http.MethodPut, path, env, &out); err != nil {
		return Network{}, err
	}
	if len(out) == 0 {
		return Network{}, fmt.Errorf("PUT %s: empty response", path)
	}
	return out[0], nil
}

// ClientDevice is a device the Network application knows about. A DHCP
// reservation is a client with UseFixedIP set; its DNS name is
// LocalDNSRecord, which the router only serves while UseFixedIP is set.
type ClientDevice struct {
	ID                    string `json:"_id,omitempty"`
	MAC                   string `json:"mac"`
	Name                  string `json:"name,omitempty"`
	Hostname              string `json:"hostname,omitempty"`
	UseFixedIP            bool   `json:"use_fixedip"`
	FixedIP               string `json:"fixed_ip,omitempty"`
	NetworkID             string `json:"network_id,omitempty"`
	LocalDNSRecord        string `json:"local_dns_record,omitempty"`
	LocalDNSRecordEnabled bool   `json:"local_dns_record_enabled"`
	LastIP                string `json:"last_ip,omitempty"`
}

// DisplayName is the client's name, falling back to its hostname.
func (d ClientDevice) DisplayName() string {
	if d.Name != "" {
		return d.Name
	}
	return d.Hostname
}

// HasDNSName reports whether the router serves a DNS name for the device.
func (d ClientDevice) HasDNSName() bool {
	return d.UseFixedIP && d.LocalDNSRecordEnabled && d.LocalDNSRecord != ""
}

// ListClients returns every client the Network application knows about.
func (c *Client) ListClients(ctx context.Context) ([]ClientDevice, error) {
	return cachedList(c, ctx, &c.clientCache, &c.clientTime, func() ([]ClientDevice, error) {
		var env classicEnvelope
		if err := c.do(ctx, http.MethodGet, c.classic("/rest/user"), nil, &env); err != nil {
			return nil, err
		}
		var out []ClientDevice
		err := decodeClassic(http.MethodGet, "/rest/user", env, &out)
		return out, err
	})
}

// GetClient returns the client with the given ID, or an error satisfying IsNotFound.
func (c *Client) GetClient(ctx context.Context, id string) (ClientDevice, error) {
	clients, err := c.ListClients(ctx)
	if err != nil {
		return ClientDevice{}, err
	}
	for _, d := range clients {
		if d.ID == id {
			return d, nil
		}
	}
	return ClientDevice{}, notFound("rest/user/" + id)
}

// CreateClient adds a client, e.g. a reservation for a device not seen yet.
// fields uses the API's names: mac, name, use_fixedip, fixed_ip, network_id,
// local_dns_record, local_dns_record_enabled.
func (c *Client) CreateClient(ctx context.Context, fields map[string]any) (ClientDevice, error) {
	return c.writeClient(ctx, http.MethodPost, "/rest/user", fields)
}

// UpdateClient changes the given fields of a client and returns it as stored.
func (c *Client) UpdateClient(ctx context.Context, id string, fields map[string]any) (ClientDevice, error) {
	return c.writeClient(ctx, http.MethodPut, "/rest/user/"+id, fields)
}

func (c *Client) writeClient(ctx context.Context, method, path string, fields map[string]any) (ClientDevice, error) {
	var env classicEnvelope
	if err := c.write(ctx, method, c.classic(path), fields, &env); err != nil {
		return ClientDevice{}, err
	}
	var out []ClientDevice
	if err := decodeClassic(method, path, env, &out); err != nil {
		return ClientDevice{}, err
	}
	if len(out) == 0 {
		return ClientDevice{}, fmt.Errorf("%s %s: empty response", method, path)
	}
	return out[0], nil
}

// ForgetClient removes a client entirely, including its name and history.
func (c *Client) ForgetClient(ctx context.Context, mac string) error {
	var env classicEnvelope
	return c.write(ctx, http.MethodPost, c.classic("/cmd/stamgr"),
		map[string]any{"cmd": "forget-sta", "macs": []string{mac}}, &env)
}

func notFound(path string) error {
	return &APIError{Method: http.MethodGet, Path: path, Status: http.StatusNotFound, Message: "not found"}
}

// cachedList returns a fresh copy of the cached list if it is younger than
// CacheTTL, or fetches it. cacheMu is held while fetching, so concurrent
// callers share one request.
func cachedList[T any](c *Client, _ context.Context, cache *[]T, at *time.Time, fetch func() ([]T, error)) ([]T, error) {
	if c.cfg.CacheTTL <= 0 {
		out, err := fetch()
		if out == nil && err == nil {
			out = []T{}
		}
		return out, err
	}
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if *cache != nil && time.Since(*at) < c.cfg.CacheTTL {
		return append([]T(nil), (*cache)...), nil
	}
	out, err := fetch()
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []T{}
	}
	*cache, *at = out, time.Now()
	return append([]T(nil), out...), nil
}

// Lease is a DHCP lease as reported by the router (active-leases): which
// device has which address, and until when. Reserved devices (UseFixedIP)
// also have leases.
type Lease struct {
	IP             string  `json:"ip"`
	MAC            string  `json:"mac"`
	Hostname       string  `json:"hostname"`
	Name           string  `json:"name"`
	DisplayName    string  `json:"display_name"`
	OUI            string  `json:"oui"` // manufacturer, from the MAC address
	NetworkID      string  `json:"network_id"`
	Status         string  `json:"status"`      // "online" or "offline"
	ClientType     string  `json:"client_type"` // "WIRED" or "WIRELESS"
	UseFixedIP     bool    `json:"use_fixedip"`
	FixedIP        string  `json:"fixed_ip"`
	LocalDNSRecord string  `json:"local_dns_record"`
	ExpiresUnix    float64 `json:"lease_expiration_time"` // seconds since 1970; 0 if unknown
}

// Label is the best available name for the device: the name set in the web
// UI, else the router's display name, else the device's host name. For
// unnamed devices the router appends the last two bytes of the MAC address to
// the display name ("iPhone d1:21"); that suffix is dropped.
func (l Lease) Label() string {
	if l.Name != "" {
		return l.Name
	}
	if d := l.DisplayName; d != "" {
		if len(l.MAC) == 17 {
			d = strings.TrimSuffix(d, " "+l.MAC[12:])
		}
		return d
	}
	return l.Hostname
}

// Expires returns when the lease expires, or the zero time if unknown.
func (l Lease) Expires() time.Time {
	if l.ExpiresUnix <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(l.ExpiresUnix), 0)
}

// ListLeases returns the router's current DHCP leases.
func (c *Client) ListLeases(ctx context.Context) ([]Lease, error) {
	var out struct {
		Info []Lease `json:"dhcp_lease_info"`
	}
	if err := c.do(ctx, http.MethodGet, c.v2("/active-leases"), nil, &out); err != nil {
		return nil, err
	}
	if out.Info == nil {
		out.Info = []Lease{}
	}
	return out.Info, nil
}
