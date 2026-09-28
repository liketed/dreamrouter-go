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
