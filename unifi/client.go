// Package unifi talks to the UniFi Network application on a UniFi OS gateway
// such as the Dream Router 7: static DNS records, clients (DHCP reservations
// and per-client DNS names) and networks.
//
// It is the API client shared by drctl and the dreamrouter Terraform
// provider. It uses the Network application's internal API, the same one its
// web UI uses; Ubiquiti doesn't document it.
package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

// Config holds the connection settings.
type Config struct {
	Host               string // host or host:port, optionally with scheme
	Site               string // defaults to "default"
	Username, Password string // a local UniFi OS account
	InsecureSkipVerify bool   // the router's certificate is self-signed out of the box

	// LoginRetryTimeout is how long to keep retrying a login refused with
	// HTTP 429 because the router's login limit was reached. 0 fails at once.
	LoginRetryTimeout time.Duration

	// CacheTTL lets reads reuse a list of DNS records or clients fetched
	// within this time, so many concurrent readers (e.g. Terraform resources
	// refreshing) share one request. Any write drops the cache. 0 disables it.
	CacheTTL time.Duration

	// Logf, if set, receives progress messages such as
	// "router login limit reached, retrying in 5s".
	Logf func(ctx context.Context, msg string)

	// RetryIntervals overrides the waits between rate-limited login attempts
	// (the last one repeats); for tests.
	RetryIntervals []time.Duration
}

// Error codes returned by the router that callers commonly check for.
const (
	CodeDNSRecordAlreadyExists    = "api.err.StaticDnsRecordAlreadyExists"
	CodeDNSOverlapsWithDeviceName = "api.err.StaticDnsOverlapsWithDeviceLocalDns"
	CodeCNAMEOverlapsOtherRecords = "api.err.StaticDnsCnameAliasOverlapsWithOtherRecords"
	CodeDuplicateFixedIP          = "api.err.DuplicateFixedIP"
	CodeInvalidFixedIP            = "api.err.InvalidFixedIP"
	CodeMACUsed                   = "api.err.MacUsed"
	CodeDeviceNameRequiresFixedIP = "api.err.LocalDnsRecordRequiresFixedIp"
	CodeLoginLimitReached         = "AUTHENTICATION_FAILED_LIMIT_REACHED"
	CodeInvalidUsernameOrPassword = "AUTHENTICATION_FAILED_INVALID_CREDENTIALS"
)

// APIError is an error response from the router. The newer "v2" endpoints
// (static DNS) and the classic endpoints (clients, networks) report errors
// differently; both are normalised to Code and Message.
type APIError struct {
	Method, Path string
	Status       int
	Code         string // e.g. "api.err.DuplicateFixedIP"
	Message      string
}

func (e *APIError) Error() string {
	msg := e.Message
	if e.Code != "" && e.Code != e.Message {
		msg = fmt.Sprintf("%s (%s)", e.Message, e.Code)
	}
	if e.Status == http.StatusTooManyRequests {
		msg += "; the router limits logins per minute (success.login.limit.count in " +
			"/usr/lib/ulp-go/config.props), wait a minute and try again"
	}
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, msg)
}

// HasCode reports whether err is an APIError with the given code.
func HasCode(err error, code string) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == code
}

// IsNotFound reports whether err means the requested item doesn't exist.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}

// Client is safe for concurrent use. It logs in on first use and again if
// the session expires.
type Client struct {
	cfg     Config
	base    string
	network string // base URL of the Network application
	http    *http.Client

	mu          sync.Mutex // serialises requests; guards csrf, loggedIn, loginWaited
	csrf        string
	loggedIn    bool
	loginWaited time.Duration

	cacheMu     sync.Mutex // held while fetching, so concurrent readers share one request
	dnsCache    []DNSRecord
	dnsTime     time.Time
	clientCache []ClientDevice
	clientTime  time.Time

	retryIntervals []time.Duration
}

// Waits between login attempts after HTTP 429; the last one repeats. The
// router's limit is per minute, so the total wait rarely exceeds a minute.
var defaultRetryIntervals = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}

// New creates a client. It doesn't contact the router until the first request.
func New(cfg Config) (*Client, error) {
	if cfg.Host == "" {
		return nil, errors.New("host is required")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, errors.New("username and password are required")
	}
	if cfg.Site == "" {
		cfg.Site = "default"
	}
	jar, _ := cookiejar.New(nil)
	base := cfg.Host
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	base = strings.TrimSuffix(base, "/")
	intervals := defaultRetryIntervals
	if len(cfg.RetryIntervals) > 0 {
		intervals = cfg.RetryIntervals
	}
	return &Client{
		cfg:     cfg,
		base:    base,
		network: base + "/proxy/network",
		http: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}, //nolint:gosec
			},
		},
		retryIntervals: intervals,
	}, nil
}

// LoginWaited returns how long the client has waited in total because the
// router's login limit was reached.
func (c *Client) LoginWaited() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loginWaited
}

func (c *Client) v2(path string) string      { return c.network + "/v2/api/site/" + c.cfg.Site + path }
func (c *Client) classic(path string) string { return c.network + "/api/s/" + c.cfg.Site + path }

// invalidate drops cached lists after a write. It must not be called while
// holding mu (readers hold cacheMu while waiting for mu).
func (c *Client) invalidate() {
	c.cacheMu.Lock()
	c.dnsCache, c.clientCache = nil, nil
	c.cacheMu.Unlock()
}

// write performs a request that changes something, then drops the cache.
func (c *Client) write(ctx context.Context, method, url string, body, out any) error {
	err := c.do(ctx, method, url, body, out)
	c.invalidate()
	return err
}

// do sends an authenticated request, logging in first if needed and again if
// the session has expired. out receives the decoded response body.
func (c *Client) do(ctx context.Context, method, url string, body, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 1; ; attempt++ {
		if err := c.loginLocked(ctx); err != nil {
			return err
		}
		err := c.send(ctx, method, url, body, out)
		var apiErr *APIError
		if attempt == 1 && errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			c.loggedIn = false
			continue
		}
		return err
	}
}

// classicEnvelope is how classic endpoints wrap results:
// {"meta":{"rc":"ok"},"data":[...]}.
type classicEnvelope struct {
	Data json.RawMessage `json:"data"`
}

func decodeClassic(method, path string, env classicEnvelope, out any) error {
	if out != nil && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("%s %s: unexpected response: %w", method, path, err)
		}
	}
	return nil
}

// loginLocked logs in if there is no session, retrying while the router's
// login limit is reached, until LoginRetryTimeout. The caller holds mu.
func (c *Client) loginLocked(ctx context.Context) error {
	if c.loggedIn {
		return nil
	}
	body := map[string]any{"username": c.cfg.Username, "password": c.cfg.Password, "rememberMe": false}
	start := time.Now()
	deadline := start.Add(c.cfg.LoginRetryTimeout)
	for attempt := 0; ; attempt++ {
		err := c.send(ctx, http.MethodPost, c.base+"/api/auth/login", body, nil)
		if err == nil {
			c.loggedIn = true
			return nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusTooManyRequests {
			return fmt.Errorf("logging in to %s as %q: %w", c.base, c.cfg.Username, err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if c.cfg.LoginRetryTimeout > 0 {
				err = fmt.Errorf("still refused after retrying for %s: %w", time.Since(start).Round(time.Second), err)
			}
			return fmt.Errorf("logging in to %s as %q: %w", c.base, c.cfg.Username, err)
		}
		wait := min(c.retryIntervals[min(attempt, len(c.retryIntervals)-1)], remaining)
		if c.cfg.Logf != nil {
			c.cfg.Logf(ctx, fmt.Sprintf("router login limit reached, retrying in %s", wait.Round(time.Millisecond)))
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("logging in to %s: %w", c.base, ctx.Err())
		case <-time.After(wait):
		}
		c.loginWaited += wait
	}
}

// send performs one HTTP request. The caller holds mu.
func (c *Client) send(ctx context.Context, method, url string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if t := resp.Header.Get("X-Updated-CSRF-Token"); t != "" {
		c.csrf = t
	} else if t := resp.Header.Get("X-CSRF-Token"); t != "" {
		c.csrf = t
	}
	path := strings.TrimPrefix(strings.TrimPrefix(url, c.network), c.base)
	if resp.StatusCode >= 400 {
		return parseError(method, path, resp.StatusCode, raw)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: unexpected response: %w", method, path, err)
		}
	}
	return nil
}

// parseError understands both error formats:
//
//	v2 and login: {"code":"api.err.X","message":"Human text"}
//	classic:      {"meta":{"rc":"error","msg":"api.err.X"},"data":[]}
func parseError(method, path string, status int, raw []byte) error {
	e := &APIError{Method: method, Path: path, Status: status}
	var payload struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Meta    struct {
			Msg string `json:"msg"`
		} `json:"meta"`
	}
	_ = json.Unmarshal(raw, &payload)
	switch {
	case payload.Message != "":
		e.Code, e.Message = payload.Code, payload.Message
	case payload.Meta.Msg != "":
		e.Code, e.Message = payload.Meta.Msg, describeCode(payload.Meta.Msg)
	default:
		e.Message = http.StatusText(status)
	}
	return e
}

// describeCode turns the classic API's bare error codes into readable text.
func describeCode(code string) string {
	switch code {
	case CodeDuplicateFixedIP:
		return "the IP address is already reserved for another device"
	case CodeInvalidFixedIP:
		return "the IP address is not valid for the network"
	case CodeMACUsed:
		return "a client with this MAC address already exists"
	case CodeDeviceNameRequiresFixedIP:
		return "a device's DNS name requires a fixed IP address"
	case "api.err.InvalidPayload":
		return "the router rejected the request as invalid"
	case "api.err.NotFound":
		return "not found"
	}
	return code
}
