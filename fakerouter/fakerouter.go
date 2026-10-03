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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
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
	Note                  string `json:"note,omitempty"`
	Noted                 bool   `json:"noted,omitempty"`
	Blocked               bool   `json:"blocked,omitempty"`
}

// Status is a connected or recently seen device, as listed by clients/active
// and clients/history.
type Status struct {
	MAC           string  `json:"mac"`
	IP            string  `json:"ip,omitempty"`
	LastIP        string  `json:"last_ip,omitempty"`
	DisplayName   string  `json:"display_name,omitempty"`
	Hostname      string  `json:"hostname,omitempty"`
	OUI           string  `json:"oui,omitempty"`
	ModelName     string  `json:"model_name,omitempty"`
	Status        string  `json:"status"`
	Type          string  `json:"type"`
	IsWired       bool    `json:"is_wired"`
	Blocked       bool    `json:"blocked"`
	UseFixedIP    bool    `json:"use_fixedip"`
	NetworkID     string  `json:"network_id,omitempty"`
	NetworkName   string  `json:"network_name,omitempty"`
	UplinkName    string  `json:"last_uplink_name,omitempty"`
	SwitchPort    float64 `json:"sw_port,omitempty"`
	WiredRateMbps float64 `json:"wired_rate_mbps,omitempty"`
	ESSID         string  `json:"essid,omitempty"`
	Radio         string  `json:"radio,omitempty"`
	RadioProto    string  `json:"radio_proto,omitempty"`
	Channel       float64 `json:"channel,omitempty"`
	Signal        float64 `json:"signal,omitempty"`
	TxBytes       float64 `json:"tx_bytes,omitempty"`
	RxBytes       float64 `json:"rx_bytes,omitempty"`
	Uptime        float64 `json:"uptime,omitempty"`
	FirstSeen     float64 `json:"first_seen,omitempty"`
	LastSeen      float64 `json:"last_seen,omitempty"`
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
	active    []Status
	offline   []Status
	stat      Stat
	forwards  []map[string]any

	autoBackups []AutoBackup
	staged      map[string][]byte // uploaded backups by backup_id
	schedule    map[string]any    // the super_mgmt setting
	restores    int
}

// AutoBackup is one of the router's automatic backups.
type AutoBackup struct {
	Filename string
	Version  string
	Time     time.Time
	Data     []byte
}

// fakeBackupMagic starts the fake router's backups: a JSON snapshot of its
// DNS records, clients, networks and port forwards. Real backups are
// encrypted .unf files the fake doesn't read.
const fakeBackupMagic = "FAKEUNF\n"

// FakeVersion is the Network application version the fake reports in backups.
const FakeVersion = "10.6.106"

type backupState struct {
	DNS      []DNSRecord      `json:"dns"`
	Clients  []Client         `json:"clients"`
	Networks []map[string]any `json:"networks"`
	Forwards []map[string]any `json:"forwards"`
}

// Backup returns a backup of the current state, as DownloadBackup would.
func (r *Router) Backup() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.backupLocked()
}

func (r *Router) backupLocked() []byte {
	b, _ := json.Marshal(backupState{DNS: r.dns, Clients: r.clients, Networks: r.networks, Forwards: r.forwards})
	return append([]byte(fakeBackupMagic), b...)
}

// PutAutoBackup adds an automatic backup.
func (r *Router) PutAutoBackup(b AutoBackup) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.autoBackups = append(r.autoBackups, b)
}

// AutoBackups returns the automatic backups.
func (r *Router) AutoBackups() []AutoBackup {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]AutoBackup(nil), r.autoBackups...)
}

// Restores counts completed restores.
func (r *Router) Restores() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.restores
}

// BackupSchedule returns the stored super_mgmt setting.
func (r *Router) BackupSchedule() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := map[string]any{}
	for k, v := range r.schedule {
		c[k] = v
	}
	return c
}

func (r *Router) cmdBackup(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	var body struct {
		Cmd      string `json:"cmd"`
		Days     int    `json:"days"`
		Filename string `json:"filename"`
		BackupID string `json:"backup_id"`
	}
	_ = json.NewDecoder(req.Body).Decode(&body)
	switch body.Cmd {
	case "list-backups":
		out := []map[string]any{}
		for _, b := range r.autoBackups {
			out = append(out, map[string]any{"filename": b.Filename, "version": b.Version, "time": b.Time.UnixMilli(),
				"size": len(b.Data), "type": "primary", "keep_forever": false})
		}
		classicOK(w, out)
	case "backup":
		classicOK(w, []map[string]any{{"url": "/dl/backup/" + FakeVersion + ".unf"}})
	case "delete-backup":
		for i, b := range r.autoBackups {
			if b.Filename == body.Filename {
				r.autoBackups = append(r.autoBackups[:i], r.autoBackups[i+1:]...)
				classicOK(w, []any{})
				return
			}
		}
		classicErr(w, http.StatusBadRequest, "api.err.InvalidBackup")
	case "restore":
		data, ok := r.staged[body.BackupID]
		if !ok {
			// The real router fails with an internal error for an unknown ID.
			http.Error(w, "HTTP Status 500 – Internal Server Error", http.StatusInternalServerError)
			return
		}
		var st backupState
		_ = json.Unmarshal(data[len(fakeBackupMagic):], &st)
		r.dns, r.clients, r.networks, r.forwards = st.DNS, st.Clients, st.Networks, st.Forwards
		delete(r.staged, body.BackupID)
		r.restores++
		// The restart ends every session.
		r.sessions = map[string]bool{}
		classicOK(w, []any{})
	default:
		classicErr(w, http.StatusNotFound, "api.err.NotFound")
	}
}

func (r *Router) downloadBackup(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	var data []byte
	switch {
	case strings.HasPrefix(req.URL.Path, "/proxy/network/dl/backup/"):
		data = r.backupLocked()
	case strings.HasPrefix(req.URL.Path, "/proxy/network/dl/autobackup/"):
		name := strings.TrimPrefix(req.URL.Path, "/proxy/network/dl/autobackup/")
		for _, b := range r.autoBackups {
			if b.Filename == name {
				data = b.Data
			}
		}
	}
	if data == nil {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func (r *Router) uploadBackup(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	if err := req.ParseMultipartForm(32 << 20); err != nil {
		classicErr(w, http.StatusBadRequest, "the request doesn't contain a multipart/form-data or multipart/mixed stream")
		return
	}
	var data []byte
	var name string
	for _, files := range req.MultipartForm.File {
		for _, fh := range files {
			f, err := fh.Open()
			if err == nil {
				data, _ = io.ReadAll(f)
				f.Close()
				name = fh.Filename
			}
		}
	}
	if !bytes.HasPrefix(data, []byte(fakeBackupMagic)) || !json.Valid(data[len(fakeBackupMagic):]) {
		classicErr(w, http.StatusBadRequest, "api.err.InvalidBackup")
		return
	}
	if r.staged == nil {
		r.staged = map[string][]byte{}
	}
	id := fmt.Sprintf("00000000-0000-4000-8000-%012d", r.nextID+1)
	r.nextID++
	r.staged[id] = data
	classicOK(w, []map[string]any{{"backup_id": id, "version": FakeVersion, "filename": name, "filesize": len(data),
		"timestamp": "1791055953534", "sites": []map[string]any{{"name": "default", "desc": "Default"}}, "purpose": "application_backup"}})
}

func (r *Router) settings(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	if req.Method == http.MethodPut {
		if req.URL.Path != "/proxy/network/api/s/default/rest/setting/super_mgmt/"+r.schedule["_id"].(string) {
			classicErr(w, http.StatusBadRequest, "api.err.IdInvalid")
			return
		}
		var body map[string]any
		_ = json.NewDecoder(req.Body).Decode(&body)
		for k, v := range body {
			r.schedule[k] = v
		}
		classicOK(w, []map[string]any{r.schedule})
		return
	}
	classicOK(w, []map[string]any{r.schedule, {"_id": "set-ntp", "key": "ntp", "setting_preference": "auto"}})
}

// PortForwards returns the stored port forwarding rules, as raw JSON objects.
func (r *Router) PortForwards() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]map[string]any, len(r.forwards))
	for i, f := range r.forwards {
		c := map[string]any{}
		for k, v := range f {
			c[k] = v
		}
		out[i] = c
	}
	return out
}

// PutPortForward stores a rule as given (no validation) and returns its ID.
func (r *Router) PutPortForward(f map[string]any) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.id()
	c := map[string]any{"_id": id}
	for k, v := range f {
		c[k] = v
	}
	r.forwards = append(r.forwards, c)
	return id
}

// ModifyPortForward changes a stored rule, as an edit in the web UI would.
func (r *Router) ModifyPortForward(id string, fn func(map[string]any)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.forwards {
		if f["_id"] == id {
			fn(f)
		}
	}
}

// RemovePortForward deletes a stored rule, as the web UI would.
func (r *Router) RemovePortForward(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, f := range r.forwards {
		if f["_id"] == id {
			r.forwards = append(r.forwards[:i], r.forwards[i+1:]...)
			return
		}
	}
}

// pfPortCount checks a port field as the router does (numbers 1–65535,
// ranges in either order, lists) and returns how many ports it covers.
func pfPortCount(v any) (int, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return 0, false
	}
	n := 0
	for _, item := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(item, "-")
		a, errA := strconv.Atoi(lo)
		b := a
		var errB error
		if isRange {
			b, errB = strconv.Atoi(hi)
		}
		if errA != nil || errB != nil || a < 1 || a > 65535 || b < 1 || b > 65535 {
			return 0, false
		}
		if b < a {
			a, b = b, a
		}
		n += b - a + 1
	}
	return n, true
}

// pfInvalid mirrors the router's own checks on a port forwarding rule,
// including that only a single port can be forwarded to a different one. Like
// the router, it accepts duplicates, reversed ranges, addresses outside the
// LANs or of the router, unknown WAN interfaces and a missing enabled field.
func pfInvalid(f map[string]any) string {
	name, _ := f["name"].(string)
	if name == "" {
		return "api.err.InvalidPayload"
	}
	n, ok := pfPortCount(f["dst_port"])
	if !ok {
		return "api.err.InvalidPayload"
	}
	if fp, present := f["fwd_port"]; present && fp != "" {
		m, ok := pfPortCount(fp)
		if !ok {
			return "api.err.InvalidPayload"
		}
		// Only a single port can be translated; ranges and lists must be
		// forwarded to the same ports.
		if m != n || (n > 1 && fp != f["dst_port"]) {
			return "api.err.IncorrectMultiportFwdPort"
		}
	}
	if ip, _ := f["fwd"].(string); net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
		return "api.err.InvalidPayload"
	}
	switch f["proto"] {
	case "tcp", "udp", "tcp_udp":
	default:
		return "api.err.InvalidPayload"
	}
	if src, ok := f["src"].(string); ok && src != "any" {
		if net.ParseIP(src) == nil {
			if _, _, err := net.ParseCIDR(src); err != nil {
				return "api.err.InvalidPayload"
			}
		}
	}
	return ""
}

func (r *Router) portForwards(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	id := strings.TrimPrefix(strings.TrimPrefix(req.URL.Path, "/proxy/network/api/s/default/rest/portforward"), "/")
	find := func() int {
		for i, f := range r.forwards {
			if f["_id"] == id {
				return i
			}
		}
		return -1
	}
	var body map[string]any
	if req.Method == http.MethodPost || req.Method == http.MethodPut {
		_ = json.NewDecoder(req.Body).Decode(&body)
	}
	switch {
	case req.Method == http.MethodGet && id == "":
		classicOK(w, r.forwards)
	case req.Method == http.MethodPost && id == "":
		if code := pfInvalid(body); code != "" {
			classicErr(w, http.StatusBadRequest, code)
			return
		}
		body["_id"] = r.id()
		delete(body, "site_id")
		r.forwards = append(r.forwards, body)
		classicOK(w, []map[string]any{body})
	case req.Method == http.MethodPut && id != "":
		i := find()
		if i < 0 {
			classicErr(w, http.StatusBadRequest, "api.err.IdInvalid")
			return
		}
		merged := map[string]any{}
		for k, v := range r.forwards[i] {
			merged[k] = v
		}
		for k, v := range body {
			merged[k] = v
		}
		merged["_id"] = id
		if code := pfInvalid(merged); code != "" {
			classicErr(w, http.StatusBadRequest, code)
			return
		}
		r.forwards[i] = merged
		classicOK(w, []map[string]any{merged})
	case req.Method == http.MethodDelete && id != "":
		i := find()
		if i < 0 {
			classicErr(w, http.StatusBadRequest, "api.err.IdInvalid")
			return
		}
		r.forwards = append(r.forwards[:i], r.forwards[i+1:]...)
		classicOK(w, []any{})
	default:
		classicErr(w, http.StatusBadRequest, "api.err.InvalidRequest")
	}
}

// Stat is what the router reports for stat/health, stat/sysinfo and
// stat/device, as raw JSON objects. Defaults resemble a Dream Router 7 with
// one access point; change them with ModifyStat.
type Stat struct {
	Health  []map[string]any
	Sysinfo map[string]any
	Devices []map[string]any
}

func defaultStat() Stat {
	return Stat{
		Health: []map[string]any{
			{"subsystem": "wlan", "status": "ok", "num_user": 21, "num_guest": 1, "num_ap": 1},
			{"subsystem": "wan", "status": "ok", "wan_ip": "203.0.113.7", "num_sta": 42, "isp_name": "Example ISP", "asn": 64500,
				"gw_system-stats": map[string]any{"cpu": "13.9", "mem": "58.2", "uptime": "581852"},
				"uptime_stats":    map[string]any{"WAN": map[string]any{"availability": 99.5, "latency_average": 6}}},
			{"subsystem": "www", "status": "ok", "latency": 15, "uptime": 196631, "drops": 2},
			{"subsystem": "lan", "status": "ok", "num_user": 20, "num_guest": 0, "num_sw": 1},
			{"subsystem": "vpn", "status": "unknown"},
		},
		Sysinfo: map[string]any{"name": "Dream Router 7", "version": "10.6.106", "console_display_version": "5.1.33",
			"timezone": "Europe/Dublin", "uptime": 581855, "update_available": false},
		Devices: []map[string]any{
			{"type": "udm", "model": "UDMA67A", "name": "Dream Router 7", "mac": "94:2a:6f:00:00:01", "ip": "203.0.113.7",
				"version": "5.1.33.34087", "upgradable": false, "state": 1, "uptime": 581852, "num_sta": 42,
				"system-stats": map[string]any{"cpu": "13.9", "mem": "58.2", "uptime": "581852"},
				"sys_stats":    map[string]any{"loadavg_1": "2.75", "mem_total": 3009642496, "mem_used": 1752711168},
				"temperatures": []any{map[string]any{"name": "CPU", "type": "cpu", "value": 60.5}},
				"uplink":       map[string]any{"name": "ppp0", "ip": "203.0.113.7", "up": true, "speed": 10000, "latency": 15},
				"wan1":         map[string]any{"name": "eth3", "ip": "203.0.113.7", "up": true, "speed": 2500, "latency": 5},
				"speedtest-status": map[string]any{"rundate": 0, "xput_download": 0.0, "xput_upload": 0.0, "latency": 0,
					"server": map[string]any{"provider": "", "city": ""}}},
			{"type": "uap", "model": "U7PRO", "name": "U7 Pro", "mac": "94:2a:6f:00:00:02", "ip": "192.168.1.3",
				"version": "8.7.11.19419", "upgradable": false, "state": 1, "uptime": 990000, "num_sta": 18},
		},
	}
}

// ModifyStat changes what the status endpoints report.
func (r *Router) ModifyStat(fn func(*Stat)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fn(&r.stat)
}

func (r *Router) statHandler(data func() any) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !r.authorised(w, req) {
			return
		}
		classicOK(w, data())
	}
}

// PutActive adds a connected device to clients/active.
func (r *Router) PutActive(s Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s.Status = "online"
	r.active = append(r.active, s)
}

// PutOffline adds a recently seen, now offline device to clients/history.
func (r *Router) PutOffline(s Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s.Status = "offline"
	r.offline = append(r.offline, s)
}

// statusList returns the list with each device's blocked and reservation
// state from its client record, as the real router reports them.
func (r *Router) statusList(list []Status) []Status {
	out := make([]Status, 0, len(list))
	for _, s := range list {
		for _, c := range r.clients {
			if c.MAC == s.MAC {
				s.Blocked, s.UseFixedIP = c.Blocked, c.UseFixedIP
			}
		}
		out = append(out, s)
	}
	return out
}

func (r *Router) clientsActive(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	writeJSON(w, http.StatusOK, r.statusList(r.active))
}

func (r *Router) clientsHistory(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.authorised(w, req) {
		return
	}
	writeJSON(w, http.StatusOK, r.statusList(r.offline))
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
	mux.HandleFunc("/proxy/network/v2/api/site/default/clients/active", r.clientsActive)
	mux.HandleFunc("/proxy/network/v2/api/site/default/clients/history", r.clientsHistory)
	mux.HandleFunc("/proxy/network/api/s/default/rest/networkconf", r.networkCollection)
	mux.HandleFunc("/proxy/network/api/s/default/rest/networkconf/", r.networkItem)
	mux.HandleFunc("/proxy/network/api/s/default/rest/user", r.userCollection)
	mux.HandleFunc("/proxy/network/api/s/default/rest/user/", r.userItem)
	mux.HandleFunc("/proxy/network/api/s/default/cmd/stamgr", r.stamgr)
	mux.HandleFunc("/proxy/network/api/s/default/cmd/backup", r.cmdBackup)
	mux.HandleFunc("/proxy/network/dl/backup/", r.downloadBackup)
	mux.HandleFunc("/proxy/network/dl/autobackup/", r.downloadBackup)
	mux.HandleFunc("/proxy/network/upload/backup", r.uploadBackup)
	mux.HandleFunc("/proxy/network/api/s/default/rest/setting", r.settings)
	mux.HandleFunc("/proxy/network/api/s/default/rest/setting/", r.settings)
	r.schedule = map[string]any{"_id": "set-super-mgmt", "key": "super_mgmt", "autobackup_enabled": true,
		"autobackup_cron_expr": "30 0 1 * *", "autobackup_timezone": "Europe/Dublin", "autobackup_days": 0}
	mux.HandleFunc("/proxy/network/api/s/default/rest/portforward", r.portForwards)
	mux.HandleFunc("/proxy/network/api/s/default/rest/portforward/", r.portForwards)
	mux.HandleFunc("/proxy/network/api/s/default/stat/health", r.statHandler(func() any { return r.stat.Health }))
	mux.HandleFunc("/proxy/network/api/s/default/stat/sysinfo", r.statHandler(func() any { return []map[string]any{r.stat.Sysinfo} }))
	mux.HandleFunc("/proxy/network/api/s/default/stat/device", r.statHandler(func() any { return r.stat.Devices }))
	r.stat = defaultStat()
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
	if v, ok := f["note"].(string); ok {
		c.Note = v
	}
	if v, ok := f["noted"].(bool); ok && v {
		c.Noted = true // the real router keeps "noted" set once a note was added
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
		MAC  string   `json:"mac"`
		MACs []string `json:"macs"`
	}
	_ = json.NewDecoder(req.Body).Decode(&body)
	switch body.Cmd {
	case "block-sta", "unblock-sta":
		// The real router accepts any value, creating a client entry for an
		// unknown (or invalid) MAC address.
		block := body.Cmd == "block-sta"
		for i := range r.clients {
			if r.clients[i].MAC == body.MAC {
				r.clients[i].Blocked = block
				classicOK(w, []Client{r.clients[i]})
				return
			}
		}
		c := Client{ID: r.id(), MAC: body.MAC, Blocked: block}
		r.clients = append(r.clients, c)
		classicOK(w, []Client{c})
		return
	case "kick-sta":
		classicErr(w, http.StatusBadRequest, "api.err.UnknownStation")
		return
	case "forget-sta":
	default:
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
