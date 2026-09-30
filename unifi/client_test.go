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
