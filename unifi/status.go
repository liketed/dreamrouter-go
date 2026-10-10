package unifi

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Status is an overview of the router: versions, internet connection,
// system load, client counts, firmware and the last speed test. It combines
// stat/health, stat/sysinfo and the router's own entry in stat/device.
type Status struct {
	Name           string // e.g. "Dream Router 7"
	Model          string // e.g. "UDMA67A"
	OSVersion      string // UniFi OS, e.g. "5.1.33"
	NetworkVersion string // UniFi Network application, e.g. "10.6.106"
	Timezone       string
	Uptime         time.Duration

	Internet InternetStatus
	System   SystemStatus

	// Clients connected now: Wired + WiFi = Clients, Guests among them.
	Clients, Wired, WiFi, Guests int
	AccessPoints, Switches       int

	// Devices are the UniFi devices: the router itself, access points and
	// switches, with their firmware.
	Devices []DeviceStatus

	// UpdateAvailable is true if the Network application or any device's
	// firmware can be updated.
	UpdateAvailable bool

	SpeedTest SpeedTest

	// WANs is the live state of every internet connection's port (Internet
	// covers only the first).
	WANs []WANLink

	// Subsystems is each part's health: "wan", "www" (internet), "lan",
	// "wlan", "vpn", with "ok", "warning", "error" or "unknown".
	Subsystems map[string]string
}

// InternetStatus describes the WAN connection (the first WAN only).
type InternetStatus struct {
	Status         string // "ok" if the internet is reachable ("www" health)
	Up             bool   // WAN link up
	IP             string // public (WAN) IP address
	ISP            string
	ASN            int
	Interface      string  // WAN port, e.g. "eth3"
	LinkMbps       int     // WAN port link speed
	LatencyMs      int     // to the internet
	Availability   float64 // percent, from the router's WAN monitors
	Drops          int     // internet connection drops counted by the router
	InternetUptime time.Duration
	PPPoE          bool // connected over PPPoE
}

// SystemStatus is the router's load.
type SystemStatus struct {
	CPUPercent    float64
	MemoryPercent float64
	MemoryTotal   int64 // bytes
	MemoryUsed    int64 // bytes
	Load1         float64
	CPUTempC      float64 // 0 if not reported
	Overheating   bool
}

// DeviceStatus is a UniFi device (router, access point or switch).
type DeviceStatus struct {
	Name       string
	Model      string
	Type       string // "udm" (router), "uap" (access point), "usw" (switch), ...
	MAC        string
	IP         string
	Version    string // firmware
	Upgradable bool
	UpgradeTo  string // available firmware, if any
	Online     bool
	Uptime     time.Duration
	Clients    int
}

// SpeedTest is the router's last speed test. Zero if never run.
type SpeedTest struct {
	Run          time.Time
	DownloadMbps float64
	UploadMbps   float64
	PingMs       float64
	Server       string // e.g. "Vodafone Ireland, Dublin"
}

// flexNum decodes a JSON number or a number in a string (the router uses both).
type flexNum float64

func (f *flexNum) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil // ignore values that aren't numbers rather than fail the whole status
	}
	*f = flexNum(v)
	return nil
}

type rawHealth struct {
	Subsystem   string              `json:"subsystem"`
	Status      string              `json:"status"`
	NumUser     int                 `json:"num_user"`
	NumGuest    int                 `json:"num_guest"`
	NumSta      int                 `json:"num_sta"`
	NumAP       int                 `json:"num_ap"`
	NumSw       int                 `json:"num_sw"`
	WANIP       string              `json:"wan_ip"`
	ISPName     string              `json:"isp_name"`
	ASN         int                 `json:"asn"`
	Latency     flexNum             `json:"latency"`
	Uptime      flexNum             `json:"uptime"`
	Drops       int                 `json:"drops"`
	UptimeStats map[string]rawUpMon `json:"uptime_stats"`
}

type rawUpMon struct {
	Availability flexNum `json:"availability"`
}

type rawSysinfo struct {
	Name            string  `json:"name"`
	Version         string  `json:"version"`
	DisplayVersion  string  `json:"console_display_version"`
	Timezone        string  `json:"timezone"`
	Uptime          flexNum `json:"uptime"`
	UpdateAvailable bool    `json:"update_available"`
}

type rawPort struct {
	Name    string  `json:"name"`
	IP      string  `json:"ip"`
	Up      bool    `json:"up"`
	Speed   int     `json:"speed"`
	Latency flexNum `json:"latency"`
}

type rawDevice struct {
	Name        string  `json:"name"`
	Model       string  `json:"model"`
	Type        string  `json:"type"`
	MAC         string  `json:"mac"`
	IP          string  `json:"ip"`
	Version     string  `json:"version"`
	Upgradable  bool    `json:"upgradable"`
	UpgradeTo   string  `json:"upgrade_to_firmware"`
	State       int     `json:"state"`
	Uptime      flexNum `json:"uptime"`
	NumSta      int     `json:"num_sta"`
	Overheating bool    `json:"overheating"`
	SystemStats struct {
		CPU flexNum `json:"cpu"`
		Mem flexNum `json:"mem"`
	} `json:"system-stats"`
	SysStats struct {
		Load1    flexNum `json:"loadavg_1"`
		MemTotal flexNum `json:"mem_total"`
		MemUsed  flexNum `json:"mem_used"`
	} `json:"sys_stats"`
	Temperatures []struct {
		Type  string  `json:"type"`
		Value flexNum `json:"value"`
	} `json:"temperatures"`
	Uplink    rawPort `json:"uplink"`
	WAN1      rawPort `json:"wan1"`
	WAN2      rawPort `json:"wan2"`
	SpeedTest struct {
		RunDate      flexNum `json:"rundate"`
		XputDownload flexNum `json:"xput_download"`
		XputUpload   flexNum `json:"xput_upload"`
		Latency      flexNum `json:"latency"`
		Server       struct {
			Provider string `json:"provider"`
			City     string `json:"city"`
		} `json:"server"`
	} `json:"speedtest-status"`
}

// isGateway reports whether the device is the router (UniFi OS console or gateway).
func (d rawDevice) isGateway() bool {
	switch d.Type {
	case "udm", "ugw", "uxg":
		return true
	}
	return false
}

func (c *Client) classicGet(ctx context.Context, path string, out any) error {
	var env classicEnvelope
	if err := c.do(ctx, http.MethodGet, c.classic(path), nil, &env); err != nil {
		return err
	}
	return decodeClassic(http.MethodGet, path, env, out)
}

// GetStatus returns an overview of the router.
func (c *Client) GetStatus(ctx context.Context) (Status, error) {
	var health []rawHealth
	if err := c.classicGet(ctx, "/stat/health", &health); err != nil {
		return Status{}, err
	}
	var sysinfo []rawSysinfo
	if err := c.classicGet(ctx, "/stat/sysinfo", &sysinfo); err != nil {
		return Status{}, err
	}
	var devices []rawDevice
	if err := c.classicGet(ctx, "/stat/device", &devices); err != nil {
		return Status{}, err
	}

	s := Status{Subsystems: map[string]string{}}
	if len(sysinfo) > 0 {
		si := sysinfo[0]
		s.Name, s.NetworkVersion, s.OSVersion, s.Timezone = si.Name, si.Version, si.DisplayVersion, si.Timezone
		s.Uptime = time.Duration(si.Uptime) * time.Second
		s.UpdateAvailable = si.UpdateAvailable
	}
	for _, h := range health {
		s.Subsystems[h.Subsystem] = h.Status
		switch h.Subsystem {
		case "wan":
			s.Internet.IP, s.Internet.ISP, s.Internet.ASN = h.WANIP, h.ISPName, h.ASN
			s.Clients = h.NumSta
			if m, ok := h.UptimeStats["WAN"]; ok {
				s.Internet.Availability = float64(m.Availability)
			}
		case "www":
			s.Internet.Status = h.Status
			s.Internet.LatencyMs, s.Internet.Drops = int(h.Latency), h.Drops
			s.Internet.InternetUptime = time.Duration(h.Uptime) * time.Second
		case "lan":
			s.Wired, s.Switches = h.NumUser+h.NumGuest, h.NumSw
			s.Guests += h.NumGuest
		case "wlan":
			s.WiFi, s.AccessPoints = h.NumUser+h.NumGuest, h.NumAP
			s.Guests += h.NumGuest
		}
	}
	if s.Clients == 0 {
		s.Clients = s.Wired + s.WiFi
	}
	for _, d := range devices {
		s.Devices = append(s.Devices, DeviceStatus{
			Name: d.Name, Model: d.Model, Type: d.Type, MAC: d.MAC, IP: d.IP, Version: d.Version,
			Upgradable: d.Upgradable, UpgradeTo: d.UpgradeTo, Online: d.State == 1,
			Uptime: time.Duration(d.Uptime) * time.Second, Clients: d.NumSta,
		})
		if d.Upgradable {
			s.UpdateAvailable = true
		}
		if !d.isGateway() {
			continue
		}
		if s.Name == "" {
			s.Name = d.Name
		}
		s.Model = d.Model
		s.System = SystemStatus{
			CPUPercent: float64(d.SystemStats.CPU), MemoryPercent: float64(d.SystemStats.Mem),
			MemoryTotal: int64(d.SysStats.MemTotal), MemoryUsed: int64(d.SysStats.MemUsed),
			Load1: float64(d.SysStats.Load1), Overheating: d.Overheating,
		}
		for _, t := range d.Temperatures {
			if t.Type == "cpu" || s.System.CPUTempC == 0 {
				s.System.CPUTempC = float64(t.Value)
			}
		}
		s.Internet.Up, s.Internet.Interface, s.Internet.LinkMbps = d.WAN1.Up, d.WAN1.Name, d.WAN1.Speed
		for group, l := range map[string]rawPort{"WAN": d.WAN1, "WAN2": d.WAN2} {
			if l.Name != "" {
				s.WANs = append(s.WANs, WANLink{NetworkGroup: group, Interface: l.Name, Up: l.Up, IP: l.IP})
			}
		}
		sort.Slice(s.WANs, func(i, j int) bool { return s.WANs[i].NetworkGroup < s.WANs[j].NetworkGroup })
		if s.Internet.IP == "" {
			s.Internet.IP = d.WAN1.IP
		}
		if s.Internet.LatencyMs == 0 {
			s.Internet.LatencyMs = int(d.Uplink.Latency)
		}
		s.Internet.PPPoE = strings.HasPrefix(d.Uplink.Name, "ppp")
		if st := d.SpeedTest; st.RunDate > 0 {
			s.SpeedTest = SpeedTest{
				Run: time.Unix(int64(st.RunDate), 0), DownloadMbps: float64(st.XputDownload),
				UploadMbps: float64(st.XputUpload), PingMs: float64(st.Latency),
				Server: strings.Trim(st.Server.Provider+", "+st.Server.City, ", "),
			}
		}
	}
	return s, nil
}
