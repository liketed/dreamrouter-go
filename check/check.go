// Package check validates DNS records, MAC addresses and DHCP reservations
// before they are sent to the router. The rules mirror the router's own, so
// mistakes are reported clearly and up front instead of as the router's often
// terse errors.
package check

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/liketed/dreamrouter-go/unifi"
)

// RecordTypes are the static DNS record types the router supports.
var RecordTypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT"}

// Which optional numeric fields each type may set to a non-zero value; the
// router rejects others ("MX record may not have a value set on ... ttl").
var allowedFields = map[string]map[string]bool{
	"A":     {"ttl": true},
	"AAAA":  {"ttl": true},
	"CNAME": {"ttl": true},
	"MX":    {"priority": true},
	"NS":    {},
	"SRV":   {"priority": true, "weight": true, "port": true},
	"TXT":   {},
}

// FieldAllowed reports whether a record of type t may set field ("ttl",
// "priority", "weight" or "port") to a non-zero value.
func FieldAllowed(t, field string) bool { return allowedFields[t][field] }

var (
	// Names end up in dnsmasq config lines such as host-record=NAME,IP, so
	// whitespace and commas would corrupt them.
	namePattern = regexp.MustCompile(`^[^\s,]+$`)
	srvPattern  = regexp.MustCompile(`^_[^.\s,]+\._[^.\s,]+\.[^\s,]+$`)
)

// NormalizeType upper-cases a record type and checks it is supported.
func NormalizeType(t string) (string, error) {
	t = strings.ToUpper(strings.TrimSpace(t))
	for _, rt := range RecordTypes {
		if t == rt {
			return t, nil
		}
	}
	return "", fmt.Errorf("unsupported record type %q (supported: %s)", t, strings.Join(RecordTypes, ", "))
}

// NormalizeName trims whitespace and a trailing dot from a DNS name.
func NormalizeName(name string) string {
	return strings.TrimSuffix(strings.TrimSpace(name), ".")
}

// Name checks a DNS name.
func Name(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("name %q must not be empty or contain whitespace or commas", name)
	}
	return nil
}

// DNSInput is a DNS record to validate. A nil field is unknown (e.g. only
// known after a Terraform apply) and is skipped.
type DNSInput struct {
	Type, Name, Value           *string
	TTL, Priority, Weight, Port *int64
}

// DNSProblems returns every rule the record breaks, keyed by field ("type",
// "name", "value", "ttl", "priority", "weight", "port"). Messages are complete
// sentences.
func DNSProblems(in DNSInput) map[string]string {
	problems := map[string]string{}
	if in.Name != nil && !namePattern.MatchString(*in.Name) {
		problems["name"] = "name must not be empty or contain whitespace or commas"
	}
	numbers := map[string]*int64{"ttl": in.TTL, "priority": in.Priority, "weight": in.Weight, "port": in.Port}
	for field, v := range numbers {
		if v != nil && (*v < 0 || (field != "ttl" && *v > 65535) || *v > 2147483647) {
			max := "65535"
			if field == "ttl" {
				max = "2147483647"
			}
			problems[field] = fmt.Sprintf("%s must be between 0 and %s", field, max)
		}
	}
	if in.Type == nil {
		return problems
	}
	t, err := NormalizeType(*in.Type)
	if err != nil {
		problems["type"] = err.Error()
		return problems
	}
	for field, v := range numbers {
		if v != nil && *v != 0 && !allowedFields[t][field] && problems[field] == "" {
			problems[field] = fmt.Sprintf("%s cannot be set for %s records (only %s)", field, t, describeAllowed(field))
		}
	}
	if in.Name != nil && t == "SRV" && problems["name"] == "" && !srvPattern.MatchString(NormalizeName(*in.Name)) {
		problems["name"] = `SRV records need a name of the form "_service._protocol.domain", e.g. "_sip._tcp.home.internal"`
	}
	if in.Value == nil {
		return problems
	}
	v := strings.TrimSpace(*in.Value)
	switch t {
	case "A":
		if a, err := netip.ParseAddr(v); err != nil || !a.Is4() {
			problems["value"] = fmt.Sprintf("value must be an IPv4 address for A records (got %q)", *in.Value)
		}
	case "AAAA":
		if a, err := netip.ParseAddr(v); err != nil || !a.Is6() || a.Is4In6() {
			problems["value"] = fmt.Sprintf("value must be an IPv6 address for AAAA records (got %q)", *in.Value)
		}
	case "NS":
		if _, err := netip.ParseAddr(v); err != nil {
			problems["value"] = fmt.Sprintf("value must be the IPv4 or IPv6 address of the DNS server to forward the name to "+
				"(the router implements NS records as conditional forwarders) (got %q)", *in.Value)
		}
	case "CNAME", "MX", "SRV":
		switch {
		case !namePattern.MatchString(NormalizeName(v)):
			problems["value"] = fmt.Sprintf("value must be a hostname for %s records (no whitespace or commas)", t)
		case t == "CNAME" && in.Name != nil && strings.EqualFold(NormalizeName(v), NormalizeName(*in.Name)):
			problems["value"] = "a CNAME cannot point to itself"
		}
	case "TXT":
		if msg := txtProblem(*in.Value); msg != "" {
			problems["value"] = msg
		}
	}
	return problems
}

// DNSRecord validates a complete record and normalises it: the type is
// upper-cased, trailing dots are trimmed from names, and IP addresses are
// written in canonical form. It returns the first problem (in field order).
func DNSRecord(r *unifi.DNSRecord) error {
	in := DNSInput{Type: &r.RecordType, Name: &r.Key, Value: &r.Value,
		TTL: &r.TTL, Priority: &r.Priority, Weight: &r.Weight, Port: &r.Port}
	if problems := DNSProblems(in); len(problems) > 0 {
		for _, field := range []string{"type", "name", "value", "ttl", "priority", "weight", "port"} {
			if msg, ok := problems[field]; ok {
				return fmt.Errorf("%s", msg)
			}
		}
	}
	r.RecordType, _ = NormalizeType(r.RecordType)
	r.Key = NormalizeName(r.Key)
	switch r.RecordType {
	case "A", "AAAA", "NS":
		a, _ := netip.ParseAddr(strings.TrimSpace(r.Value))
		r.Value = a.String()
	case "CNAME", "MX", "SRV":
		r.Value = NormalizeName(r.Value)
	}
	return nil
}

// txtProblem mirrors the router's rules: double quotes only around the whole
// value, and each line at most 255 characters.
func txtProblem(v string) string {
	if v == "" {
		return "TXT value must not be empty"
	}
	inner := v
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		inner = v[1 : len(v)-1]
	}
	if strings.Contains(inner, `"`) {
		return `TXT value: double quotes are only allowed around the whole value, e.g. "\"hello world\""`
	}
	for _, line := range strings.Split(v, "\n") {
		if len(line) > 255 {
			return "TXT value: each line must be at most 255 characters"
		}
	}
	return ""
}

func describeAllowed(field string) string {
	var types []string
	for _, t := range RecordTypes {
		if allowedFields[t][field] {
			types = append(types, t)
		}
	}
	return strings.Join(types, ", ") + " records"
}

// MAC normalises a MAC address to lower-case colon form (aa:bb:cc:dd:ee:ff),
// accepting colons, dashes or dots as separators.
func MAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("invalid MAC address %q", s)
	}
	return hw.String(), nil
}

// IPv4 parses an IPv4 address.
func IPv4(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !a.Is4() {
		return netip.Addr{}, fmt.Errorf("invalid IPv4 address %q", s)
	}
	return a, nil
}

// NetworkFor picks the network a reservation belongs to: the one named (by
// name or ID, if name is set) or the one whose subnet contains ip. It checks
// that ip is a usable host address in that subnet.
func NetworkFor(networks []unifi.Network, ip netip.Addr, name string) (unifi.Network, error) {
	var candidates []unifi.Network
	for _, n := range networks {
		if n.Subnet == "" {
			continue
		}
		if name != "" && !strings.EqualFold(n.Name, name) && n.ID != name {
			continue
		}
		candidates = append(candidates, n)
	}
	if name != "" && len(candidates) == 0 {
		return unifi.Network{}, fmt.Errorf("no network named %q (networks: %s)", name, NetworkNames(networks))
	}
	for _, n := range candidates {
		prefix, err := netip.ParsePrefix(n.Subnet)
		if err != nil || !prefix.Masked().Contains(ip) {
			continue
		}
		p := prefix.Masked()
		if ip == p.Addr() || ip == broadcast(p) {
			return unifi.Network{}, fmt.Errorf("%s is the network or broadcast address of %s", ip, p)
		}
		if ip == prefix.Addr() {
			return unifi.Network{}, fmt.Errorf("%s is the router's own address on network %q", ip, n.Name)
		}
		return n, nil
	}
	if name != "" {
		return unifi.Network{}, fmt.Errorf("%s is not in network %q (%s)", ip, candidates[0].Name, candidates[0].Subnet)
	}
	return unifi.Network{}, fmt.Errorf("%s is not in any network's subnet (networks: %s)", ip, NetworkNames(networks))
}

func broadcast(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= (1 << (32 - p.Bits())) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// NetworkNames lists networks with a subnet as "Name 192.168.1.1/24, ...".
func NetworkNames(networks []unifi.Network) string {
	var names []string
	for _, n := range networks {
		if n.Subnet != "" {
			names = append(names, fmt.Sprintf("%s %s", n.Name, n.Subnet))
		}
	}
	if len(names) == 0 {
		return "none"
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// dnsmasqValue matches values that are safe inside a comma-separated dnsmasq
// option line. (The router itself accepts commas and spaces, which would
// corrupt the line it generates.)
var dnsmasqValue = regexp.MustCompile(`^[^\s,]+$`)

// Boot checks network boot settings: server must be an IPv4 address (dnsmasq
// needs an address there) and file a single token without commas.
func Boot(server, file string) error {
	if _, err := IPv4(server); err != nil {
		return fmt.Errorf("boot server %q must be an IPv4 address", server)
	}
	if !dnsmasqValue.MatchString(file) {
		return fmt.Errorf("boot file %q must not be empty or contain spaces or commas", file)
	}
	return nil
}

// TFTPServer checks a TFTP server (DHCP option 66): a host name or IP address
// without spaces or commas.
func TFTPServer(s string) error {
	if !dnsmasqValue.MatchString(s) {
		return fmt.Errorf("TFTP server %q must be a host name or IP address without spaces or commas", s)
	}
	return nil
}

// Lease time limits: dnsmasq raises anything under 2 minutes to 2 minutes,
// and the router refuses more than a year.
const (
	MinLeaseTime = 120
	MaxLeaseTime = 365 * 24 * 3600
)

// LeaseTime checks a DHCP lease time in seconds.
func LeaseTime(seconds int) error {
	if seconds < MinLeaseTime || seconds > MaxLeaseTime {
		return fmt.Errorf("lease time %ds must be between 2 minutes (%d) and a year (%d)", seconds, MinLeaseTime, MaxLeaseTime)
	}
	return nil
}

// DHCPDNS checks the DNS servers to hand out by DHCP: up to four distinct
// IPv4 addresses (none means the router itself). The router accepts host
// names, lists and IPv6 addresses here, which DHCP can't hand out.
func DHCPDNS(servers []string) error {
	return ipv4List("DNS server", servers, 4)
}

// NTPServers checks the NTP servers to hand out by DHCP: up to two distinct
// IPv4 addresses.
func NTPServers(servers []string) error {
	return ipv4List("NTP server", servers, 2)
}

func ipv4List(what string, servers []string, max int) error {
	if len(servers) > max {
		return fmt.Errorf("at most %d %ss can be handed out, not %d", max, what, len(servers))
	}
	seen := map[string]bool{}
	for _, s := range servers {
		a, err := IPv4(s)
		if err != nil || a.String() != strings.TrimSpace(s) {
			return fmt.Errorf("%s %q must be an IPv4 address", what, s)
		}
		if seen[a.String()] {
			return fmt.Errorf("%s %s is listed twice", what, a)
		}
		seen[a.String()] = true
	}
	return nil
}

var domainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// DomainName checks a network's domain name (handed out by DHCP as the
// search domain), e.g. "home.internal".
func DomainName(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("domain name %q must be 1 to 253 characters", name)
	}
	for _, label := range strings.Split(name, ".") {
		if !domainLabel.MatchString(label) {
			return fmt.Errorf("domain name %q must be lower-case letters, digits and hyphens, separated by dots", name)
		}
	}
	return nil
}

// privateNets are the address ranges a new network may use (RFC 1918). The
// router itself also accepts public subnets, which would hide those
// internet addresses from every device on the network.
var privateNets = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
}

// NewNetwork checks a new network against the existing ones and fills in
// a default DHCP range (.6 to the last address but one, like the web UI):
// a unique name, a VLAN from 2 to 4094 not in use, a private subnet given
// as the router's address on it that overlaps no other network, a DHCP
// range inside it, and the DNS servers to hand out.
func NewNetwork(spec *unifi.NetworkSpec, existing []unifi.Network) error {
	spec.Name = strings.TrimSpace(spec.Name)
	if spec.Name == "" {
		return fmt.Errorf("a network needs a name")
	}
	if spec.VLAN < 2 || spec.VLAN > 4094 {
		return fmt.Errorf("VLAN %d must be from 2 to 4094", spec.VLAN)
	}
	p, err := netip.ParsePrefix(spec.Subnet)
	if err != nil || !p.Addr().Is4() {
		return fmt.Errorf("subnet %q must be the router's address with a prefix, e.g. 192.168.30.1/24", spec.Subnet)
	}
	m := p.Masked()
	if p.Bits() > 30 {
		return fmt.Errorf("subnet %s is too small; use a /30 or larger, e.g. a /24", spec.Subnet)
	}
	if p.Addr() == m.Addr() || p.Addr() == broadcast(m) {
		return fmt.Errorf("subnet %q must be given as the router's address on it, e.g. %s", spec.Subnet, m.Addr().Next().String()+"/"+strconv.Itoa(p.Bits()))
	}
	private := false
	for _, n := range privateNets {
		if n.Contains(m.Addr()) && n.Bits() <= m.Bits() {
			private = true
		}
	}
	if !private {
		return fmt.Errorf("subnet %s is not a private range (10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16); devices couldn't reach those internet addresses", m)
	}
	for _, n := range existing {
		if strings.EqualFold(n.Name, spec.Name) {
			return fmt.Errorf("a network named %q already exists", n.Name)
		}
		if int(n.VLAN) == spec.VLAN && n.VLANEnabled {
			return fmt.Errorf("network %q already uses VLAN %d", n.Name, spec.VLAN)
		}
		if op, err := netip.ParsePrefix(n.Subnet); err == nil && op.Masked().Overlaps(m) {
			return fmt.Errorf("subnet %s overlaps network %q (%s)", m, n.Name, op.Masked())
		}
	}
	if spec.DHCPStart == "" && spec.DHCPStop == "" {
		a := m.Addr()
		for i := 0; i < 6 && a.Next().IsValid(); i++ {
			a = a.Next()
		}
		if !m.Contains(a) || a.Compare(broadcast(m)) >= 0 {
			a = p.Addr().Next()
		}
		spec.DHCPStart, spec.DHCPStop = a.String(), broadcast(m).Prev().String()
	}
	start, errS := IPv4(spec.DHCPStart)
	stop, errE := IPv4(spec.DHCPStop)
	switch {
	case errS != nil || errE != nil:
		return fmt.Errorf("DHCP range %s - %s must be IPv4 addresses", spec.DHCPStart, spec.DHCPStop)
	case !m.Contains(start) || !m.Contains(stop) || start == m.Addr() || stop == broadcast(m):
		return fmt.Errorf("DHCP range %s - %s must be inside %s", start, stop, m)
	case stop.Less(start):
		return fmt.Errorf("DHCP range %s - %s is reversed", start, stop)
	case start.Compare(p.Addr()) <= 0 && p.Addr().Compare(stop) <= 0:
		return fmt.Errorf("DHCP range %s - %s includes the router's address %s", start, stop, p.Addr())
	}
	return DHCPDNS(spec.DNS)
}

var hex64 = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// WiFiPassword checks a WPA passphrase: 8 to 63 printable ASCII characters,
// or exactly 64 hex digits (a raw key). The router also accepts 64
// characters that aren't hex, which no device could use.
func WiFiPassword(pw string) error {
	if hex64.MatchString(pw) {
		return nil
	}
	if len(pw) < 8 || len(pw) > 63 {
		return fmt.Errorf("a Wi-Fi password must be 8 to 63 characters (or 64 hex digits), not %d", len(pw))
	}
	for _, r := range pw {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("a Wi-Fi password may only contain printable ASCII characters")
		}
	}
	return nil
}

// WiFiBands checks the bands to broadcast on: "2g", "5g" and "6g".
func WiFiBands(bands []string) error {
	if len(bands) == 0 {
		return fmt.Errorf("give at least one band: 2g, 5g or 6g")
	}
	seen := map[string]bool{}
	for _, b := range bands {
		switch b {
		case "2g", "5g", "6g":
		default:
			return fmt.Errorf("band %q must be 2g, 5g or 6g", b)
		}
		if seen[b] {
			return fmt.Errorf("band %s is listed twice", b)
		}
		seen[b] = true
	}
	return nil
}

// NewWiFi checks a new Wi-Fi network: a name (SSID) of 1 to 32 bytes that
// no other Wi-Fi network uses (the router accepts duplicates, which would
// confuse every device), a valid password, valid bands, and an existing
// network to attach it to.
func NewWiFi(spec *unifi.WiFiSpec, existing []unifi.WiFi, networks []unifi.Network) error {
	if spec.Name == "" || len(spec.Name) > 32 {
		return fmt.Errorf("a Wi-Fi network name must be 1 to 32 bytes, not %d", len(spec.Name))
	}
	for _, w := range existing {
		if w.Name == spec.Name {
			return fmt.Errorf("a Wi-Fi network named %q already exists", w.Name)
		}
	}
	if err := WiFiPassword(spec.Password); err != nil {
		return err
	}
	if len(spec.Bands) == 0 {
		spec.Bands = []string{"2g", "5g"}
	}
	if err := WiFiBands(spec.Bands); err != nil {
		return err
	}
	for _, n := range networks {
		if n.ID == spec.NetworkID {
			return nil
		}
	}
	return fmt.Errorf("no network with ID %q", spec.NetworkID)
}
