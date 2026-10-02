// Package fakerouter is an in-memory stand-in for a Dream Router 7's UniFi OS
// login and Network application API, for tests. It mimics behaviour observed
// on a real router: cookie + CSRF sessions, the v2 static DNS API (no GET by
// ID, full records returned from POST/PUT), the classic client (DHCP
// reservation) and network API with its error codes, and the login limit.
//
// Tests can also change the router behind a client's back (as someone using
// the web UI would) with PutDNS, ModifyDNS, RemoveDNS, PutClient and
// ExpireSessions.
package fakerouter

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
)

const (
	Username  = "admin"
	Password  = "secret"
	NetworkID = "net-default"
)

type DNSRecord struct {
	ID         string `json:"_id"`
	RecordType string `json:"record_type"`
	Key        string `json:"key"`
	Value      string `json:"value"`
	Enabled    bool   `json:"enabled"`
	TTL        int64  `json:"ttl"`
	Priority   int64  `json:"priority"`
	Weight     int64  `json:"weight"`
	Port       int64  `json:"port"`
}

type Client struct {
	ID                    string `json:"_id"`
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

type Router struct {
	*httptest.Server

	mu        sync.Mutex
	dns       []DNSRecord
	clients   []Client
	nextID    int
	sessions  map[string]bool
	logins    int
	limit     int // successful logins allowed in total before 429; 0 = unlimited
	listCalls int
	networks  []map[string]any
	leases    []Lease
}

// Lease is a DHCP lease, as listed by active-leases.
type Lease struct {
	IP             string  `json:"ip"`
	MAC            string  `json:"mac"`
	Hostname       string  `json:"hostname,omitempty"`
	Name           string  `json:"name,omitempty"`
	DisplayName    string  `json:"display_name,omitempty"`
	OUI            string  `json:"oui,omitempty"`
	NetworkID      string  `json:"network_id"`
	Status         string  `json:"status,omitempty"`
	ClientType     string  `json:"client_type,omitempty"`
	UseFixedIP     bool    `json:"use_fixedip"`
	FixedIP        string  `json:"fixed_ip,omitempty"`
	LocalDNSRecord string  `json:"local_dns_record,omitempty"`
	ExpiresUnix    float64 `json:"lease_expiration_time"`
}

// PutLease adds a DHCP lease, as if a device had been given an address.
func (r *Router) PutLease(l Lease) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if l.NetworkID == "" {
		l.NetworkID = NetworkID
	}
	r.leases = append(r.leases, l)
}

func (r *Router) activeLeases(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	// Reservations made since the lease was handed out show in the listing,
	// as on the real router.
	out := make([]Lease, 0, len(r.leases))
	for _, l := range r.leases {
		for _, c := range r.clients {
			if c.MAC == l.MAC {
				l.UseFixedIP, l.FixedIP = c.UseFixedIP, c.FixedIP
				if c.LocalDNSRecordEnabled {
					l.LocalDNSRecord = c.LocalDNSRecord
				}
			}
		}
		out = append(out, l)
	}
	writeJSON(w, http.StatusOK, map[string]any{"dhcp_lease_info": out})
}

// New starts a fake router with one network, "Default", 192.168.1.1/24.
func New() *Router {
	r := &Router{sessions: map[string]bool{}, networks: []map[string]any{
		{"_id": NetworkID, "name": "Default", "purpose": "corporate", "ip_subnet": "192.168.1.1/24",
			"dhcpd_enabled": true, "dhcpd_start": "192.168.1.6", "dhcpd_stop": "192.168.1.254", "domain_name": "localdomain"},
		{"_id": "net-wan", "name": "Internet 1", "purpose": "wan"},
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", r.login)
	mux.HandleFunc("/proxy/network/v2/api/site/default/static-dns", r.dnsCollection)
	mux.HandleFunc("/proxy/network/v2/api/site/default/static-dns/", r.dnsItem)
	mux.HandleFunc("/proxy/network/v2/api/site/default/active-leases", r.activeLeases)
	mux.HandleFunc("/proxy/network/api/s/default/rest/networkconf", r.networkCollection)
	mux.HandleFunc("/proxy/network/api/s/default/rest/networkconf/", r.networkItem)
	mux.HandleFunc("/proxy/network/api/s/default/rest/user", r.userCollection)
	mux.HandleFunc("/proxy/network/api/s/default/rest/user/", r.userItem)
	mux.HandleFunc("/proxy/network/api/s/default/cmd/stamgr", r.stamgr)
	r.Server = httptest.NewTLSServer(mux)
	return r
}

// Host returns host:port of the server.
func (r *Router) Host() string { return strings.TrimPrefix(r.URL, "https://") }

func (r *Router) id() string { r.nextID++; return fmt.Sprintf("%024x", r.nextID) }

// DNS returns a copy of the static DNS records.
func (r *Router) DNS() []DNSRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]DNSRecord(nil), r.dns...)
}

// Clients returns a copy of the clients.
func (r *Router) Clients() []Client {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Client(nil), r.clients...)
}

// PutDNS stores a record directly and returns its ID.
func (r *Router) PutDNS(rec DNSRecord) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec.ID = r.id()
	r.dns = append(r.dns, rec)
	return rec.ID
}

// PutClient stores a client directly (e.g. a device seen on the network).
func (r *Router) PutClient(c Client) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	c.ID = r.id()
	r.clients = append(r.clients, c)
	return c.ID
}

// Client returns the client with the given MAC.
func (r *Router) Client(mac string) (Client, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.clients {
		if c.MAC == mac {
			return c, true
		}
	}
	return Client{}, false
}

// ModifyDNS changes a stored record directly.
func (r *Router) ModifyDNS(id string, fn func(*DNSRecord)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.dns {
		if r.dns[i].ID == id {
			fn(&r.dns[i])
		}
	}
}

// RemoveDNS deletes a stored record directly.
func (r *Router) RemoveDNS(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, rec := range r.dns {
		if rec.ID == id {
			r.dns = append(r.dns[:i], r.dns[i+1:]...)
			return
		}
	}
}

// ModifyClient changes a stored client directly.
func (r *Router) ModifyClient(mac string, fn func(*Client)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.clients {
		if r.clients[i].MAC == mac {
			fn(&r.clients[i])
		}
	}
}

// ExpireSessions logs every client out, as if their sessions timed out.
func (r *Router) ExpireSessions() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions = map[string]bool{}
}

// SetLoginLimit sets how many successful logins are allowed in total before
// the router answers 429 (0 = unlimited), e.g. to simulate the limit resetting.
func (r *Router) SetLoginLimit(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limit = n
}

// LoginCount returns the number of successful logins so far.
func (r *Router) LoginCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.logins
}

// ListCalls returns how many times static DNS records were listed.
func (r *Router) ListCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listCalls
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// v2 and login error format.
func v2Err(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"code": code, "message": msg, "errorCode": status})
}

// Classic error format.
func classicErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"meta": map[string]any{"rc": "error", "msg": code}, "data": []any{}})
}

func classicOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, map[string]any{"meta": map[string]any{"rc": "ok"}, "data": data})
}

func (r *Router) login(w http.ResponseWriter, req *http.Request) {
	var body struct{ Username, Password string }
	_ = json.NewDecoder(req.Body).Decode(&body)
	r.mu.Lock()
	defer r.mu.Unlock()
	if body.Username != Username || body.Password != Password {
		v2Err(w, http.StatusForbidden, "AUTHENTICATION_FAILED_INVALID_CREDENTIALS", "Invalid username or password")
		return
	}
	if r.limit > 0 && r.logins >= r.limit {
		v2Err(w, http.StatusTooManyRequests, "AUTHENTICATION_FAILED_LIMIT_REACHED", "You've reached the login attempt limit")
		return
	}
	r.logins++
	token := fmt.Sprintf("session-%d", r.logins)
	r.sessions[token] = true
	http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: token, Path: "/"})
	w.Header().Set("X-CSRF-Token", "csrf-1")
	writeJSON(w, http.StatusOK, map[string]any{"username": Username})
}

func (r *Router) authorised(w http.ResponseWriter, req *http.Request) bool {
	c, err := req.Cookie("TOKEN")
	if err != nil || !r.sessions[c.Value] {
		v2Err(w, http.StatusUnauthorized, "api.err.UserNotAuthenticated", "User not authenticated")
		return false
	}
	if req.Method != http.MethodGet && req.Header.Get("X-CSRF-Token") != "csrf-1" {
		v2Err(w, http.StatusForbidden, "api.err.InvalidCsrf", "Invalid CSRF token")
		return false
	}
	return true
}

// ---- static DNS (v2) ----

func (r *Router) dnsCollection(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	switch req.Method {
	case http.MethodGet:
		r.listCalls++
		if r.dns == nil {
			writeJSON(w, http.StatusOK, []DNSRecord{})
			return
		}
		writeJSON(w, http.StatusOK, r.dns)
	case http.MethodPost:
		var rec DNSRecord
		_ = json.NewDecoder(req.Body).Decode(&rec)
		if !r.validateDNS(w, rec, "") {
			return
		}
		rec.ID = r.id()
		r.dns = append(r.dns, rec)
		writeJSON(w, http.StatusOK, rec)
	default:
		v2Err(w, http.StatusMethodNotAllowed, "", "Method Not Allowed")
	}
}

func (r *Router) dnsItem(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	id := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
	idx := -1
	for i, rec := range r.dns {
		if rec.ID == id {
			idx = i
		}
	}
	if req.Method != http.MethodPut && req.Method != http.MethodDelete {
		v2Err(w, http.StatusMethodNotAllowed, "", "Method Not Allowed")
		return
	}
	if idx < 0 {
		v2Err(w, http.StatusNotFound, "api.err.StaticDnsRecordNotFound", "Static DNS Record not found")
		return
	}
	if req.Method == http.MethodDelete {
		r.dns = append(r.dns[:idx], r.dns[idx+1:]...)
		w.WriteHeader(http.StatusOK)
		return
	}
	var rec DNSRecord
	_ = json.NewDecoder(req.Body).Decode(&rec)
	if !r.validateDNS(w, rec, id) {
		return
	}
	rec.ID = id
	r.dns[idx] = rec
	writeJSON(w, http.StatusOK, rec)
}

// validateDNS applies the router's checks that matter for tests.
func (r *Router) validateDNS(w http.ResponseWriter, rec DNSRecord, selfID string) bool {
	invalid := func(msg string) bool {
		v2Err(w, http.StatusBadRequest, "api.err.StaticDnsRecordInvalidParameters", msg)
		return false
	}
	switch rec.RecordType {
	case "A":
		if ip := net.ParseIP(rec.Value); ip == nil || ip.To4() == nil {
			return invalid("Invalid IPv4 Address")
		}
	case "AAAA":
		if ip := net.ParseIP(rec.Value); ip == nil || ip.To4() != nil {
			return invalid("Invalid IPv6 Address")
		}
	case "NS":
		if net.ParseIP(rec.Value) == nil {
			return invalid("Target DNS server address must be a valid IPv4 or IPv6 Address")
		}
	case "CNAME":
		if rec.Key == rec.Value {
			return invalid("Invalid CNAME record! Domain name cannot be the same as alias name.")
		}
	case "MX", "SRV", "TXT":
	default:
		return invalid("Invalid record type")
	}
	for _, o := range r.dns {
		if o.ID == selfID || o.Key != rec.Key {
			continue
		}
		if o.RecordType == rec.RecordType && o.Value == rec.Value {
			v2Err(w, http.StatusBadRequest, "api.err.StaticDnsRecordAlreadyExists", "Static DNS Record Already Exists")
			return false
		}
		if o.RecordType == "CNAME" || rec.RecordType == "CNAME" {
			v2Err(w, http.StatusBadRequest, "api.err.StaticDnsCnameAliasOverlapsWithOtherRecords", "CNAME Alias Overlaps With Other Records")
			return false
		}
	}
	for _, c := range r.clients {
		if c.UseFixedIP && c.LocalDNSRecordEnabled && strings.EqualFold(c.LocalDNSRecord, rec.Key) {
			v2Err(w, http.StatusBadRequest, "api.err.StaticDnsOverlapsWithDeviceLocalDns", "Static DNS overlaps with device local DNS")
			return false
		}
	}
	return true
}

// ---- networks and clients (classic) ----

func (r *Router) networkCollection(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	classicOK(w, r.networks)
}

// Network returns a copy of the stored network with the given name.
func (r *Router) Network(name string) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.networks {
		if n["name"] == name {
			c := map[string]any{}
			for k, v := range n {
				c[k] = v
			}
			return c
		}
	}
	return nil
}

// ModifyNetwork changes a stored network directly, as someone using the web
// UI would.
func (r *Router) ModifyNetwork(name string, fn func(map[string]any)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.networks {
		if n["name"] == name {
			fn(n)
		}
	}
}

var digitsAndDots = regexp.MustCompile(`^[0-9.]+$`)

// networkItem updates a network, with the real router's checks for network
// boot settings: an empty or null boot file is rejected (even with boot off),
// as is boot on without a file, and a server that looks like an IP but isn't
// one. Host names, spaces and commas are accepted, as on the real router.
func (r *Router) networkItem(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	id := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
	if req.Method != http.MethodPut {
		classicErr(w, http.StatusMethodNotAllowed, "api.err.MethodNotAllowed")
		return
	}
	var fields map[string]any
	if json.NewDecoder(req.Body).Decode(&fields) != nil {
		classicErr(w, http.StatusBadRequest, "api.err.InvalidPayload")
		return
	}
	for _, n := range r.networks {
		if n["_id"] != id {
			continue
		}
		updated := map[string]any{}
		for k, v := range n {
			updated[k] = v
		}
		for k, v := range fields {
			updated[k] = v
		}
		if v, ok := fields["dhcpd_boot_filename"]; ok {
			if s, _ := v.(string); s == "" {
				classicErr(w, http.StatusBadRequest, "api.err.InvalidPayload")
				return
			}
		}
		if s, _ := updated["dhcpd_boot_server"].(string); s != "" && digitsAndDots.MatchString(s) && net.ParseIP(s) == nil {
			classicErr(w, http.StatusBadRequest, "api.err.InvalidPayload")
			return
		}
		if on, _ := updated["dhcpd_boot_enabled"].(bool); on {
			if f, _ := updated["dhcpd_boot_filename"].(string); f == "" {
				classicErr(w, http.StatusBadRequest, "api.err.InvalidPayload")
				return
			}
		}
		updated["setting_preference"] = "manual" // as the web UI does on every save
		for k := range updated {
			n[k] = updated[k]
		}
		classicOK(w, []map[string]any{n})
		return
	}
	classicErr(w, http.StatusNotFound, "api.err.NotFound")
}

func (r *Router) userCollection(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	switch req.Method {
	case http.MethodGet:
		classicOK(w, r.clients)
	case http.MethodPost:
		var fields map[string]any
		_ = json.NewDecoder(req.Body).Decode(&fields)
		mac, _ := fields["mac"].(string)
		if hw, err := net.ParseMAC(mac); err != nil || len(hw) != 6 {
			classicErr(w, http.StatusBadRequest, "api.err.InvalidPayload")
			return
		}
		for _, c := range r.clients {
			if c.MAC == mac {
				classicErr(w, http.StatusBadRequest, "api.err.MacUsed")
				return
			}
		}
		c := Client{ID: r.id(), MAC: mac}
		if !r.applyFields(w, &c, fields) {
			return
		}
		r.clients = append(r.clients, c)
		classicOK(w, []Client{c})
	default:
		classicErr(w, http.StatusMethodNotAllowed, "api.err.MethodNotAllowed")
	}
}

func (r *Router) userItem(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	id := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
	for i := range r.clients {
		if r.clients[i].ID != id {
			continue
		}
		if req.Method != http.MethodPut { // the real router has no DELETE here
			classicErr(w, http.StatusNotFound, "api.err.NotFound")
			return
		}
		var fields map[string]any
		_ = json.NewDecoder(req.Body).Decode(&fields)
		c := r.clients[i]
		if !r.applyFields(w, &c, fields) {
			return
		}
		r.clients[i] = c
		classicOK(w, []Client{c})
		return
	}
	classicErr(w, http.StatusNotFound, "api.err.NotFound")
}

// applyFields updates c from a request and applies the router's checks.
func (r *Router) applyFields(w http.ResponseWriter, c *Client, f map[string]any) bool {
	if v, ok := f["name"].(string); ok {
		c.Name = v
	}
	if v, ok := f["use_fixedip"].(bool); ok {
		c.UseFixedIP = v
	}
	if v, ok := f["fixed_ip"].(string); ok {
		c.FixedIP = v
	}
	if v, ok := f["network_id"].(string); ok {
		c.NetworkID = v
	}
	if v, ok := f["local_dns_record"].(string); ok {
		c.LocalDNSRecord = v
	}
	if v, ok := f["local_dns_record_enabled"].(bool); ok {
		c.LocalDNSRecordEnabled = v
	}
	if c.UseFixedIP {
		_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
		ip := net.ParseIP(c.FixedIP)
		if ip == nil || !subnet.Contains(ip) {
			classicErr(w, http.StatusBadRequest, "api.err.InvalidFixedIP")
			return false
		}
		for _, o := range r.clients {
			if o.ID != c.ID && o.UseFixedIP && o.FixedIP == c.FixedIP {
				classicErr(w, http.StatusBadRequest, "api.err.DuplicateFixedIP")
				return false
			}
		}
	}
	if c.LocalDNSRecordEnabled {
		if !c.UseFixedIP {
			classicErr(w, http.StatusBadRequest, "api.err.LocalDnsRecordRequiresFixedIp")
			return false
		}
		for _, d := range r.dns {
			if strings.EqualFold(d.Key, c.LocalDNSRecord) {
				classicErr(w, http.StatusBadRequest, "api.err.Invalid") // what the real router says
				return false
			}
		}
	}
	return true
}

func (r *Router) stamgr(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	var body struct {
		Cmd  string   `json:"cmd"`
		MACs []string `json:"macs"`
	}
	_ = json.NewDecoder(req.Body).Decode(&body)
	if body.Cmd != "forget-sta" {
		classicErr(w, http.StatusBadRequest, "api.err.InvalidCommand")
		return
	}
	var kept []Client
	var forgotten []Client
	for _, c := range r.clients {
		if contains(body.MACs, c.MAC) {
			forgotten = append(forgotten, c)
		} else {
			kept = append(kept, c)
		}
	}
	r.clients = kept
	classicOK(w, forgotten)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
