# dreamrouter-go

Go packages for managing a UniFi Dream Router 7 (or other UniFi OS gateway): static
DNS records, DHCP reservations, device DNS names, clients (connected devices, names,
notes, blocking) and network DHCP settings (network boot, TFTP server), through the UniFi Network application's API.

It is the shared code behind:

- [drctl](https://github.com/liketed/drctl), a command-line tool, and
- [terraform-provider-dreamrouter](https://github.com/liketed/terraform-provider-dreamrouter),
  a Terraform/OpenTofu provider.

```bash
go get github.com/liketed/dreamrouter-go
```

| Package | Contents |
|---|---|
| [`unifi`](unifi) | API client: login (with retries while the router's login limit is reached), static DNS records, clients (DHCP reservations, device DNS names, names and notes, blocking), connected and recently seen devices, port forwarding rules, the router's status (`GetStatus`: versions, internet, load, clients, firmware, speed test), current DHCP leases, networks and their DHCP settings. Optional shared cache for concurrent readers. |
| [`check`](check) | Validation that mirrors the router's rules: DNS records of every type (per field or as a single error), MAC and IPv4 addresses, which network a reserved IP belongs to, network boot / TFTP values, and port forwards (including the conflicts the router doesn't check). |
| [`fakerouter`](fakerouter) | An in-memory fake of the router's API for tests, with the router's error codes and login limit. |

## Example

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/liketed/dreamrouter-go/check"
	"github.com/liketed/dreamrouter-go/unifi"
)

func main() {
	c, err := unifi.New(unifi.Config{
		Host:               "192.168.1.1",
		Username:           "admin", // a local UniFi OS account, not a UI.com SSO account
		Password:           os.Getenv("UNIFI_PASS"),
		InsecureSkipVerify: true, // the router's certificate is self-signed out of the box
		LoginRetryTimeout:  2 * time.Minute,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	rec := unifi.DNSRecord{RecordType: "A", Key: "nas.home.internal", Value: "192.168.1.50", Enabled: true}
	if err := check.DNSRecord(&rec); err != nil {
		log.Fatal(err)
	}
	if _, err := c.CreateDNS(ctx, rec); err != nil && !unifi.HasCode(err, unifi.CodeDNSRecordAlreadyExists) {
		log.Fatal(err)
	}

	records, err := c.ListDNS(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range records {
		fmt.Println(r.RecordType, r.Key, r.Value)
	}
}
```

## Things to know about the router

These are behaviours of the router itself, found while building drctl and the provider:

- **Login limit.** The router allows 5 successful logins per minute by default
  (`success.login.limit.count` in `/usr/lib/ulp-go/config.props`, reset by firmware
  updates). Reuse one `Client`: it logs in once and keeps the session. With
  `LoginRetryTimeout`, it waits and retries when the limit is reached.
- **No single-record reads.** The API can only list all DNS records (or clients), so
  `GetDNS` and `GetClient` list and search. Set `CacheTTL` when many readers run at once.
- **Record types:** A, AAAA, CNAME, MX, NS, SRV and TXT. NS values are IP addresses: the
  router implements NS records as conditional forwarders. TXT values may only have
  double quotes around the whole value, and at most 255 characters per line.
- **DHCP reservations** are stored on the client (`use_fixedip`, `fixed_ip`,
  `network_id`). A device's DNS name (`local_dns_record`) is only served while it has a
  fixed IP. Clearing `use_fixedip` keeps the device; `ForgetClient` removes it entirely.
- **Network boot** (`dhcpd_boot_*` on a network) becomes dnsmasq's
  `dhcp-boot=...,FILE,,SERVER`; the TFTP server (`dhcpd_tftp_server`, option 66) is handed
  out whenever set, even with network boot off. The router won't accept an empty boot
  file once one is stored, and it accepts commas, spaces and host names that would break
  the dnsmasq line, so validate with `check.Boot` and `check.TFTPServer`. There are no
  per-device boot settings: reservations only hold a MAC address and IP.
- **Blocking** (`BlockClient`) accepts any value: an unknown MAC address, or something
  that isn't a MAC address at all, returns success and creates a new, blocked client
  entry. Validate with `check.MAC` and check the device exists first.
- **Connected devices** (`ListActiveClients`) and recently seen ones
  (`ListOfflineClients`) carry the live details: connection, signal, traffic, uptime.
  Traffic is counted from the network's side: `TxBytes` is what the device downloaded.
- **Port forwarding** (`rest/portforward`): the router accepts duplicate ports, reversed
  ranges, forwards to addresses outside the LANs or to the router itself, and WAN
  interfaces that don't exist. It stores a rule without an enabled setting if `enabled`
  is left out, and only translates a single port: a range or list must be forwarded to
  the same ports. Use `check.PortForward` before writing.
- **Status** (`GetStatus`) combines `stat/health`, `stat/sysinfo` and the router's entry
  in `stat/device`. Some numbers come as strings (CPU `"13.9"`), others as numbers, and
  the access point and switch counts include the router's built-in Wi-Fi and switch.
- **Notes**: clearing a note (`note: ""`) works, but the router keeps `noted` set.
- **Propagation.** Changes reach the router's DNS and DHCP server (dnsmasq) about
  10–20 seconds after the API call returns.
- This is the Network application's internal, undocumented API, the one its web UI
  uses. A UniFi Network update could change it.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
