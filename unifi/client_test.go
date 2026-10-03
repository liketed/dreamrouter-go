package unifi_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liketed/dreamrouter-go/fakerouter"
	"github.com/liketed/dreamrouter-go/unifi"
)

func newClient(t *testing.T, r *fakerouter.Router, mod func(*unifi.Config)) *unifi.Client {
	t.Helper()
	cfg := unifi.Config{Host: r.Host(), Username: fakerouter.Username, Password: fakerouter.Password, InsecureSkipVerify: true}
	if mod != nil {
		mod(&cfg)
	}
	c, err := unifi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDNSCRUD(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, func(cfg *unifi.Config) { cfg.CacheTTL = time.Minute })
	ctx := context.Background()

	created, err := c.CreateDNS(ctx, unifi.DNSRecord{RecordType: "SRV", Key: "_sip._tcp.home.internal",
		Value: "pbx.home.internal", Enabled: true, Priority: 10, Weight: 5, Port: 5060})
	if err != nil || created.ID == "" || created.Port != 5060 {
		t.Fatalf("CreateDNS = %+v, %v", created, err)
	}
	got, err := c.GetDNS(ctx, created.ID)
	if err != nil || got != created {
		t.Fatalf("GetDNS = %+v, %v", got, err)
	}
	got.Port = 5061
	if updated, err := c.UpdateDNS(ctx, got); err != nil || updated.Port != 5061 {
		t.Fatalf("UpdateDNS = %+v, %v", updated, err)
	}
	if again, _ := c.GetDNS(ctx, created.ID); again.Port != 5061 {
		t.Fatalf("cache not refreshed after write: %+v", again)
	}
	if err := c.DeleteDNS(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetDNS(ctx, created.ID); !unifi.IsNotFound(err) {
		t.Fatalf("GetDNS after delete: %v", err)
	}
	if err := c.DeleteDNS(ctx, created.ID); !unifi.IsNotFound(err) {
		t.Fatalf("second DeleteDNS: %v", err)
	}
	if _, err := c.UpdateDNS(ctx, got); !unifi.IsNotFound(err) {
		t.Fatalf("UpdateDNS of deleted record: %v", err)
	}
}

func TestErrors(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, nil)
	ctx := context.Background()
	a := unifi.DNSRecord{RecordType: "A", Key: "nas.home.internal", Value: "192.168.1.50", Enabled: true}
	if _, err := c.CreateDNS(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateDNS(ctx, a); !unifi.HasCode(err, unifi.CodeDNSRecordAlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := c.CreateDNS(ctx, unifi.DNSRecord{RecordType: "A", Key: "x", Value: "999.1.1.1"}); err == nil ||
		!strings.Contains(err.Error(), "Invalid IPv4 Address") {
		t.Fatalf("bad IP: %v", err)
	}
	bad := newClient(t, r, func(cfg *unifi.Config) { cfg.Password = "wrong" })
	if _, err := bad.ListDNS(ctx); !unifi.HasCode(err, unifi.CodeInvalidUsernameOrPassword) {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestClientsAndNetworks(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, nil)
	ctx := context.Background()

	nets, err := c.ListNetworks(ctx)
	if err != nil || len(nets) != 2 || nets[0].Name != "Default" || nets[0].Subnet != "192.168.1.1/24" || nets[0].DHCPStart != "192.168.1.6" {
		t.Fatalf("ListNetworks = %+v, %v", nets, err)
	}
	d, err := c.CreateClient(ctx, map[string]any{"mac": "aa:bb:cc:00:00:01", "name": "nas", "use_fixedip": true,
		"fixed_ip": "192.168.1.50", "network_id": fakerouter.NetworkID})
	if err != nil || d.ID == "" || !d.UseFixedIP || d.FixedIP != "192.168.1.50" {
		t.Fatalf("CreateClient = %+v, %v", d, err)
	}
	// Classic API errors are decoded, with readable messages.
	_, err = c.CreateClient(ctx, map[string]any{"mac": "aa:bb:cc:00:00:02", "use_fixedip": true, "fixed_ip": "192.168.1.50", "network_id": fakerouter.NetworkID})
	if !unifi.HasCode(err, unifi.CodeDuplicateFixedIP) || !strings.Contains(err.Error(), "already reserved for another device") {
		t.Fatalf("duplicate fixed IP: %v", err)
	}
	if _, err := c.CreateClient(ctx, map[string]any{"mac": "aa:bb:cc:00:00:01"}); !unifi.HasCode(err, unifi.CodeMACUsed) {
		t.Fatalf("MAC used: %v", err)
	}
	if _, err := c.UpdateClient(ctx, d.ID, map[string]any{"use_fixedip": false, "local_dns_record_enabled": true, "local_dns_record": "x"}); !unifi.HasCode(err, unifi.CodeDeviceNameRequiresFixedIP) {
		t.Fatalf("name without fixed IP: %v", err)
	}
	updated, err := c.UpdateClient(ctx, d.ID, map[string]any{"local_dns_record_enabled": true, "local_dns_record": "nas.home.internal"})
	if err != nil || !updated.HasDNSName() {
		t.Fatalf("UpdateClient = %+v, %v", updated, err)
	}
	if got, err := c.GetClient(ctx, d.ID); err != nil || got.LocalDNSRecord != "nas.home.internal" {
		t.Fatalf("GetClient = %+v, %v", got, err)
	}
	if err := c.ForgetClient(ctx, d.MAC); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetClient(ctx, d.ID); !unifi.IsNotFound(err) {
		t.Fatalf("GetClient after forget: %v", err)
	}
}

func TestOneLoginAndSharedCache(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, func(cfg *unifi.Config) { cfg.CacheTTL = time.Minute })
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ListDNS(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if r.LoginCount() != 1 || r.ListCalls() != 1 {
		t.Fatalf("20 concurrent reads: logins=%d lists=%d, want 1 and 1", r.LoginCount(), r.ListCalls())
	}
	if _, err := c.CreateDNS(ctx, unifi.DNSRecord{RecordType: "TXT", Key: "t.home.internal", Value: "hello"}); err != nil {
		t.Fatal(err)
	}
	if records, _ := c.ListDNS(ctx); len(records) != 1 || r.ListCalls() != 2 {
		t.Fatalf("after write: %d records, lists=%d; want the cache refreshed", len(records), r.ListCalls())
	}
}

func TestNoCacheByDefault(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, nil)
	ctx := context.Background()
	_, _ = c.ListDNS(ctx)
	r.PutDNS(fakerouter.DNSRecord{RecordType: "A", Key: "ui.home.internal", Value: "192.168.1.9", Enabled: true})
	if records, _ := c.ListDNS(ctx); len(records) != 1 {
		t.Fatalf("without CacheTTL, reads must be fresh: %d records", len(records))
	}
}

func TestCacheExpires(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, func(cfg *unifi.Config) { cfg.CacheTTL = 50 * time.Millisecond })
	ctx := context.Background()
	_, _ = c.ListDNS(ctx)
	r.PutDNS(fakerouter.DNSRecord{RecordType: "A", Key: "ui.home.internal", Value: "192.168.1.9", Enabled: true})
	time.Sleep(80 * time.Millisecond)
	if records, _ := c.ListDNS(ctx); len(records) != 1 {
		t.Fatalf("expired cache not refreshed: %d records", len(records))
	}
}

func TestRelogin(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, nil)
	ctx := context.Background()
	if _, err := c.ListDNS(ctx); err != nil {
		t.Fatal(err)
	}
	r.ExpireSessions()
	if _, err := c.ListClients(ctx); err != nil {
		t.Fatalf("after session expiry: %v", err)
	}
	if r.LoginCount() != 2 {
		t.Fatalf("logins = %d, want 2", r.LoginCount())
	}
}

// ---- login limit ----

type logs struct {
	mu   sync.Mutex
	msgs []string
}

func (l *logs) logf(_ context.Context, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, msg)
}

func (l *logs) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.msgs)
}

func retryClient(t *testing.T, r *fakerouter.Router, timeout time.Duration, l *logs) *unifi.Client {
	return newClient(t, r, func(cfg *unifi.Config) {
		cfg.LoginRetryTimeout, cfg.Logf = timeout, l.logf
		cfg.RetryIntervals = []time.Duration{20 * time.Millisecond, 40 * time.Millisecond}
	})
}

func useUpLogins(t *testing.T, r *fakerouter.Router) {
	r.SetLoginLimit(r.LoginCount() + 1)
	if _, err := newClient(t, r, nil).ListDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLoginLimitMessage(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	useUpLogins(t, r)
	_, err := newClient(t, r, nil).ListDNS(context.Background())
	if !unifi.HasCode(err, unifi.CodeLoginLimitReached) || !strings.Contains(err.Error(), "HTTP 429") ||
		!strings.Contains(err.Error(), "success.login.limit.count") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoginRetrySucceedsWhenLimitResets(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	useUpLogins(t, r)
	go func() {
		time.Sleep(150 * time.Millisecond)
		r.SetLoginLimit(0)
	}()
	l := &logs{}
	c := retryClient(t, r, 5*time.Second, l)
	if _, err := c.ListDNS(context.Background()); err != nil {
		t.Fatalf("after limit reset: %v", err)
	}
	if l.count() == 0 || !strings.HasPrefix(l.msgs[0], "router login limit reached, retrying in ") {
		t.Fatalf("log messages = %q", l.msgs)
	}
	if c.LoginWaited() < 100*time.Millisecond {
		t.Fatalf("LoginWaited = %s", c.LoginWaited())
	}
}

func TestLoginRetryGivesUp(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	useUpLogins(t, r)
	l := &logs{}
	start := time.Now()
	_, err := retryClient(t, r, 200*time.Millisecond, l).ListDNS(context.Background())
	if err == nil || !strings.Contains(err.Error(), "still refused after retrying") {
		t.Fatalf("err = %v", err)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond || elapsed > 2*time.Second || l.count() < 2 {
		t.Fatalf("gave up after %s with %d retries", elapsed, l.count())
	}
}

func TestLoginNoRetryWhenDisabled(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	useUpLogins(t, r)
	l := &logs{}
	start := time.Now()
	if _, err := retryClient(t, r, 0, l).ListDNS(context.Background()); err == nil || strings.Contains(err.Error(), "retrying") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > time.Second || l.count() != 0 {
		t.Fatal("retried although disabled")
	}
}

func TestLoginRetryStopsOnCancel(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	useUpLogins(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := retryClient(t, r, time.Minute, &logs{}).ListDNS(ctx); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
}

func TestWrongPasswordNotRetried(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	l := &logs{}
	c := newClient(t, r, func(cfg *unifi.Config) { cfg.Password, cfg.LoginRetryTimeout, cfg.Logf = "wrong", time.Minute, l.logf })
	start := time.Now()
	if _, err := c.ListDNS(context.Background()); err == nil || time.Since(start) > time.Second || l.count() != 0 {
		t.Fatalf("wrong password retried or accepted: %v", err)
	}
}

func TestUpdateNetworkBoot(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, nil)
	ctx := context.Background()

	n, err := c.UpdateNetwork(ctx, fakerouter.NetworkID, map[string]any{"dhcpd_boot_enabled": true,
		"dhcpd_boot_server": "192.168.1.20", "dhcpd_boot_filename": "netboot.xyz.efi", "dhcpd_tftp_server": "tftp.home.internal"})
	if err != nil || !n.BootEnabled || n.BootServer != "192.168.1.20" || n.BootFilename != "netboot.xyz.efi" ||
		n.TFTPServer != "tftp.home.internal" || n.DHCPStart != "192.168.1.6" {
		t.Fatalf("UpdateNetwork = %+v, %v (other settings must be kept)", n, err)
	}
	nets, _ := c.ListNetworks(ctx)
	if !nets[0].BootEnabled || nets[0].BootFilename != "netboot.xyz.efi" {
		t.Fatalf("ListNetworks after update: %+v", nets[0])
	}
	// The router's quirks, mirrored by the fake.
	for name, fields := range map[string]map[string]any{
		"empty file":      {"dhcpd_boot_filename": ""},
		"null file":       {"dhcpd_boot_filename": nil},
		"bad IP":          {"dhcpd_boot_server": "999.1.1.1"},
		"on without file": {"dhcpd_boot_enabled": true, "dhcpd_boot_filename": ""},
	} {
		if _, err := c.UpdateNetwork(ctx, fakerouter.NetworkID, fields); !unifi.HasCode(err, "api.err.InvalidPayload") {
			t.Errorf("%s: err = %v, want InvalidPayload", name, err)
		}
	}
	if _, err := c.UpdateNetwork(ctx, "nope", map[string]any{"dhcpd_boot_enabled": false}); !unifi.IsNotFound(err) {
		t.Errorf("unknown network: %v", err)
	}
}

func TestListLeases(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, nil)
	ctx := context.Background()
	if leases, err := c.ListLeases(ctx); err != nil || len(leases) != 0 {
		t.Fatalf("empty: %v %v", leases, err)
	}
	r.PutLease(fakerouter.Lease{IP: "192.168.1.37", MAC: "aa:bb:cc:00:00:37", Hostname: "tv", OUI: "Samsung",
		Status: "online", ClientType: "WIRED", ExpiresUnix: 1791058231})
	r.PutClient(fakerouter.Client{MAC: "aa:bb:cc:00:00:37", Name: "Living room TV", UseFixedIP: true, FixedIP: "192.168.1.37"})
	leases, err := c.ListLeases(ctx)
	if err != nil || len(leases) != 1 {
		t.Fatalf("ListLeases = %v, %v", leases, err)
	}
	l := leases[0]
	if l.Label() != "tv" || !l.UseFixedIP || l.Expires().Unix() != 1791058231 || l.OUI != "Samsung" {
		t.Fatalf("lease %+v", l)
	}
	for _, tc := range []struct {
		l    unifi.Lease
		want string
	}{
		{unifi.Lease{MAC: "86:23:5b:ad:d1:21", DisplayName: "iPhone d1:21", Hostname: "iphone"}, "iPhone"},
		{unifi.Lease{MAC: "86:23:5b:ad:d1:21", Name: "Steve's phone", DisplayName: "iPhone d1:21"}, "Steve's phone"},
		{unifi.Lease{MAC: "86:23:5b:ad:d1:21", Hostname: "iphone"}, "iphone"},
		{unifi.Lease{MAC: "86:23:5b:ad:d1:21", DisplayName: "Kitchen 12:34"}, "Kitchen 12:34"},
	} {
		if got := tc.l.Label(); got != tc.want {
			t.Errorf("Label(%+v) = %q, want %q", tc.l, got, tc.want)
		}
	}
	if (unifi.Lease{}).Expires() != (time.Time{}) {
		t.Fatal("unknown expiry should be the zero time")
	}
}

func TestClientStatusAndBlocking(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, nil)
	ctx := context.Background()
	r.PutClient(fakerouter.Client{MAC: "aa:bb:cc:00:00:44", Name: "speaker"})
	r.PutActive(fakerouter.Status{MAC: "aa:bb:cc:00:00:44", IP: "192.168.1.44", DisplayName: "Speaker 00:44", Type: "WIRELESS",
		ESSID: "home", Radio: "na", Signal: -61, TxBytes: 2e9, RxBytes: 1e8, Uptime: 3600})
	r.PutOffline(fakerouter.Status{MAC: "aa:bb:cc:00:00:88", LastIP: "192.168.1.88", Hostname: "old-laptop", Type: "WIRED", LastSeen: 1791013530})

	active, err := c.ListActiveClients(ctx)
	if err != nil || len(active) != 1 || active[0].Label() != "Speaker" || active[0].Address() != "192.168.1.44" || active[0].Signal != -61 || active[0].Status != "online" {
		t.Fatalf("ListActiveClients = %+v, %v", active, err)
	}
	offline, err := c.ListOfflineClients(ctx, 168)
	if err != nil || len(offline) != 1 || offline[0].Address() != "192.168.1.88" || offline[0].Label() != "old-laptop" || offline[0].Status != "offline" {
		t.Fatalf("ListOfflineClients = %+v, %v", offline, err)
	}

	for _, tc := range []struct{ display, host, want string }{
		{"Speaker 00:44", "", "Speaker"},
		{"aa:bb:cc:00:00:44", "speaker-host", "speaker-host"},
		{"aa:bb:cc:00:00:44", "", ""},
		{"", "speaker-host", "speaker-host"},
	} {
		if got := (unifi.ClientStatus{MAC: "aa:bb:cc:00:00:44", DisplayName: tc.display, Hostname: tc.host}).Label(); got != tc.want {
			t.Errorf("Label(%q, %q) = %q, want %q", tc.display, tc.host, got, tc.want)
		}
	}

	if err := c.BlockClient(ctx, "aa:bb:cc:00:00:44"); err != nil {
		t.Fatal(err)
	}
	if active, _ := c.ListActiveClients(ctx); !active[0].Blocked {
		t.Fatal("block not reflected in the active list")
	}
	if err := c.UnblockClient(ctx, "aa:bb:cc:00:00:44"); err != nil {
		t.Fatal(err)
	}
	if d, _ := r.Client("aa:bb:cc:00:00:44"); d.Blocked {
		t.Fatal("still blocked after unblock")
	}
	// Like the real router, the fake accepts a block for any value.
	if err := c.BlockClient(ctx, "nope"); err != nil {
		t.Fatal(err)
	}
	if d, ok := r.Client("nope"); !ok || !d.Blocked {
		t.Fatal("fake router should create a blocked entry for an unknown MAC, as the real one does")
	}

	clients, _ := c.ListClients(ctx)
	var speaker unifi.ClientDevice
	for _, d := range clients {
		if d.MAC == "aa:bb:cc:00:00:44" {
			speaker = d
		}
	}
	if _, err := c.UpdateClient(ctx, speaker.ID, map[string]any{"note": "on the shelf", "noted": true}); err != nil {
		t.Fatal(err)
	}
	if d, _ := r.Client("aa:bb:cc:00:00:44"); d.Note != "on the shelf" {
		t.Fatalf("note: %+v", d)
	}
}

func TestGetStatus(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, nil)
	ctx := context.Background()

	s, err := c.GetStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := unifi.Status{
		Name: "Dream Router 7", Model: "UDMA67A", OSVersion: "5.1.33", NetworkVersion: "10.6.106", Timezone: "Europe/Dublin",
		Uptime:  581855 * time.Second,
		Clients: 42, Wired: 20, WiFi: 22, Guests: 1, AccessPoints: 1, Switches: 1,
	}
	if s.Name != want.Name || s.Model != want.Model || s.OSVersion != want.OSVersion || s.NetworkVersion != want.NetworkVersion ||
		s.Timezone != want.Timezone || s.Uptime != want.Uptime || s.Clients != want.Clients || s.Wired != want.Wired ||
		s.WiFi != want.WiFi || s.Guests != want.Guests || s.AccessPoints != want.AccessPoints || s.Switches != want.Switches {
		t.Fatalf("GetStatus = %+v", s)
	}
	in := s.Internet
	if in.Status != "ok" || !in.Up || in.IP != "203.0.113.7" || in.ISP != "Example ISP" || in.ASN != 64500 || in.Interface != "eth3" ||
		in.LinkMbps != 2500 || in.LatencyMs != 15 || in.Availability != 99.5 || in.Drops != 2 || !in.PPPoE ||
		in.InternetUptime != 196631*time.Second {
		t.Fatalf("Internet = %+v", in)
	}
	// CPU and memory come as strings ("13.9"), memory sizes and temperature as numbers.
	sy := s.System
	if sy.CPUPercent != 13.9 || sy.MemoryPercent != 58.2 || sy.MemoryTotal != 3009642496 || sy.MemoryUsed != 1752711168 ||
		sy.Load1 != 2.75 || sy.CPUTempC != 60.5 || sy.Overheating {
		t.Fatalf("System = %+v", sy)
	}
	if len(s.Devices) != 2 || s.Devices[1].Name != "U7 Pro" || s.Devices[1].Version != "8.7.11.19419" || !s.Devices[1].Online ||
		s.UpdateAvailable || !s.SpeedTest.Run.IsZero() {
		t.Fatalf("Devices/updates/speed test = %+v %v %+v", s.Devices, s.UpdateAvailable, s.SpeedTest)
	}
	if s.Subsystems["vpn"] != "unknown" || s.Subsystems["www"] != "ok" {
		t.Fatalf("Subsystems = %v", s.Subsystems)
	}

	// A firmware update, a speed test, and numbers the router sends as strings.
	r.ModifyStat(func(st *fakerouter.Stat) {
		st.Devices[1]["upgradable"], st.Devices[1]["upgrade_to_firmware"] = true, "8.8.0.1"
		st.Devices[0]["speedtest-status"] = map[string]any{"rundate": 1791013530, "xput_download": 2210.4, "xput_upload": "105.2",
			"latency": 7, "server": map[string]any{"provider": "Example ISP", "city": "Dublin"}}
		st.Health[2]["latency"] = "18"
	})
	s, err = c.GetStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !s.UpdateAvailable || s.Devices[1].UpgradeTo != "8.8.0.1" {
		t.Fatalf("update not reported: %+v", s.Devices)
	}
	st := s.SpeedTest
	if st.Run.Unix() != 1791013530 || st.DownloadMbps != 2210.4 || st.UploadMbps != 105.2 || st.PingMs != 7 || st.Server != "Example ISP, Dublin" {
		t.Fatalf("SpeedTest = %+v", st)
	}
	if s.Internet.LatencyMs != 18 {
		t.Fatalf("latency as a string: %d", s.Internet.LatencyMs)
	}
}

func TestPortForwards(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, nil)
	ctx := context.Background()

	list, err := c.ListPortForwards(ctx)
	if err != nil || list == nil || len(list) != 0 {
		t.Fatalf("ListPortForwards = %v, %v", list, err)
	}
	pf := unifi.PortForward{Name: "web", Enabled: false, Interface: "wan", Source: "any", Port: "8443",
		ForwardIP: "192.168.1.20", ForwardPort: "443", Protocol: "tcp"}
	got, err := c.CreatePortForward(ctx, pf)
	if err != nil || got.ID == "" || got.Name != "web" || got.ForwardPort != "443" || got.Enabled {
		t.Fatalf("CreatePortForward = %+v, %v", got, err)
	}
	// enabled is always sent, even when false.
	if stored := r.PortForwards()[0]; stored["enabled"] != false {
		t.Fatalf("enabled not sent: %v", stored)
	}
	pf.Enabled, pf.ForwardPort = true, "8443"
	upd, err := c.UpdatePortForward(ctx, got.ID, pf)
	if err != nil || !upd.Enabled || upd.ForwardPort != "8443" || upd.ID != got.ID {
		t.Fatalf("UpdatePortForward = %+v, %v", upd, err)
	}
	// The router's own rejections come back as API errors.
	bad := pf
	bad.Name, bad.Port, bad.ForwardPort = "bad", "40100-40110", "40100-40105"
	if _, err := c.CreatePortForward(ctx, bad); !unifi.HasCode(err, unifi.CodePortRangeSizeMismatch) ||
		!strings.Contains(err.Error(), "same size") {
		t.Fatalf("range size mismatch: %v", err)
	}
	if err := c.DeletePortForward(ctx, got.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePortForward(ctx, got.ID); !unifi.IsNotFound(err) {
		t.Fatalf("deleting a deleted rule: %v (want IsNotFound)", err)
	}
	if list, _ := c.ListPortForwards(ctx); len(list) != 0 {
		t.Fatalf("left: %+v", list)
	}
}

func TestBackups(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, nil)
	ctx := context.Background()
	t1 := time.Date(2026, 8, 31, 23, 30, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 30, 23, 30, 0, 0, time.UTC)
	r.PutAutoBackup(fakerouter.AutoBackup{Filename: "autobackup_10.6.106_20260930.unf", Version: "10.6.106", Time: t2, Data: []byte("sept")})
	r.PutAutoBackup(fakerouter.AutoBackup{Filename: "autobackup_10.6.101_20260831.unf", Version: "10.6.101", Time: t1, Data: []byte("august")})

	list, err := c.ListBackups(ctx)
	if err != nil || len(list) != 2 || !list[0].Time.Equal(t1) || list[1].Filename != "autobackup_10.6.106_20260930.unf" || list[1].Size != 4 {
		t.Fatalf("ListBackups (oldest first) = %+v, %v", list, err)
	}
	if data, err := c.DownloadAutoBackup(ctx, list[0].Filename); err != nil || string(data) != "august" {
		t.Fatalf("DownloadAutoBackup = %q, %v", data, err)
	}
	for _, bad := range []string{"../x.unf", "a/b.unf", "x.txt", ""} {
		if _, err := c.DownloadAutoBackup(ctx, bad); err == nil {
			t.Errorf("DownloadAutoBackup(%q) accepted", bad)
		}
	}
	if err := c.DeleteAutoBackup(ctx, list[0].Filename); err != nil || len(r.AutoBackups()) != 1 {
		t.Fatalf("DeleteAutoBackup: %v, left %d", err, len(r.AutoBackups()))
	}

	sched, err := c.GetBackupSchedule(ctx)
	if err != nil || !sched.Enabled || sched.Cron != "30 0 1 * *" || sched.Timezone != "Europe/Dublin" {
		t.Fatalf("GetBackupSchedule = %+v, %v", sched, err)
	}
	got, err := c.SetBackupSchedule(ctx, unifi.BackupSchedule{Enabled: true, Cron: "0 3 * * 1"})
	if err != nil || got.Cron != "0 3 * * 1" || got.Timezone != "Europe/Dublin" {
		t.Fatalf("SetBackupSchedule (keeps time zone) = %+v, %v", got, err)
	}

	// Back up, change something, restore, and the change is gone.
	backup, err := c.DownloadBackup(ctx, 0)
	if err != nil || len(backup) == 0 {
		t.Fatalf("DownloadBackup: %v", err)
	}
	r.PutDNS(fakerouter.DNSRecord{RecordType: "A", Key: "restore-test.home.internal", Value: "192.168.1.250", Enabled: true})
	staged, err := c.UploadBackup(ctx, backup, "before.unf")
	if err != nil || staged.ID == "" || staged.Version != fakerouter.FakeVersion || staged.Filename != "before.unf" ||
		len(staged.Sites) != 1 || staged.Sites[0] != "default" || staged.Time.IsZero() {
		t.Fatalf("UploadBackup = %+v, %v", staged, err)
	}
	if r.Restores() != 0 || len(r.DNS()) != 1 {
		t.Fatal("uploading restored already")
	}
	if err := c.RestoreBackup(ctx, staged.ID); err != nil {
		t.Fatal(err)
	}
	if r.Restores() != 1 || len(r.DNS()) != 0 {
		t.Fatalf("restore didn't revert the change: %v", r.DNS())
	}
	// The restart ended the session; the client logs in again.
	if _, err := c.ListDNS(ctx); err != nil {
		t.Fatalf("after restore: %v", err)
	}
	if _, err := c.UploadBackup(ctx, []byte("not a backup"), "x.unf"); !unifi.HasCode(err, unifi.CodeInvalidBackup) {
		t.Fatalf("junk upload: %v", err)
	}
}

func TestSSH(t *testing.T) {
	r := fakerouter.New()
	defer r.Close()
	c := newClient(t, r, nil)
	ctx := context.Background()
	s, err := c.GetSSH(ctx)
	if err != nil || !s.Router || !s.Devices || s.DevicesUsername != "fakeadmin" || !s.DevicesPasswordAuth {
		t.Fatalf("GetSSH = %+v, %v", s, err)
	}
	if err := c.SetRouterSSH(ctx, false); err != nil || r.RouterSSH() {
		t.Fatalf("SetRouterSSH(false): %v, on=%v", err, r.RouterSSH())
	}
	if s, _ := c.GetSSH(ctx); s.Router {
		t.Fatal("GetSSH still reports router SSH on")
	}
	if err := c.SetRouterSSH(ctx, true); err != nil || !r.RouterSSH() {
		t.Fatalf("SetRouterSSH(true): %v", err)
	}
	// Setting device SSH to what it already is writes nothing (each write
	// makes the router issue a new device API token).
	if err := c.SetDevicesSSH(ctx, true); err != nil {
		t.Fatal(err)
	}
	if _, writes := r.Mgmt(); writes != 0 {
		t.Fatalf("no-op SetDevicesSSH wrote %d times", writes)
	}
	if err := c.SetDevicesSSH(ctx, false); err != nil {
		t.Fatal(err)
	}
	m, writes := r.Mgmt()
	if m["x_ssh_enabled"] != false || writes != 1 || m["x_ssh_username"] != "fakeadmin" {
		t.Fatalf("SetDevicesSSH(false): %v (%d writes)", m, writes)
	}
}
