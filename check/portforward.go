package check

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/liketed/dreamrouter-go/unifi"
)

// portRange is an inclusive range of ports.
type portRange struct{ lo, hi int }

// parsePorts parses "8443", "40010-40020", "80,443" or a mix like
// "80,8000-8010": comma-separated ports and ascending ranges, 1–65535.
func parsePorts(s string) ([]portRange, error) {
	s = strings.ReplaceAll(s, " ", "")
	if s == "" {
		return nil, fmt.Errorf("no port given")
	}
	var out []portRange
	for _, item := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(item, "-")
		a, errA := strconv.Atoi(lo)
		b := a
		var errB error
		if isRange {
			b, errB = strconv.Atoi(hi)
		}
		switch {
		case errA != nil || errB != nil || item == "":
			return nil, fmt.Errorf("%q is not a port, range (1000-2000) or list (80,443)", s)
		case a < 1 || a > 65535 || b < 1 || b > 65535:
			return nil, fmt.Errorf("port %q is outside 1–65535", item)
		case b < a:
			return nil, fmt.Errorf("range %q is reversed; write it as %d-%d", item, b, a)
		}
		out = append(out, portRange{a, b})
	}
	return out, nil
}

func portCount(rs []portRange) int {
	n := 0
	for _, r := range rs {
		n += r.hi - r.lo + 1
	}
	return n
}

func portsOverlap(a, b []portRange) bool {
	for _, x := range a {
		for _, y := range b {
			if x.lo <= y.hi && y.lo <= x.hi {
				return true
			}
		}
	}
	return false
}

// Ports checks a port, range or list and returns it in the router's form
// (no spaces), e.g. "80,443".
func Ports(s string) (string, error) {
	if _, err := parsePorts(s); err != nil {
		return "", err
	}
	return strings.ReplaceAll(s, " ", ""), nil
}

// NormalizeProtocol returns the router's protocol name: "tcp", "udp" or
// "tcp_udp" (also accepting "both" and "tcp/udp").
func NormalizeProtocol(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return "tcp", nil
	case "udp":
		return "udp", nil
	case "tcp_udp", "both", "tcp/udp", "":
		return "tcp_udp", nil
	}
	return "", fmt.Errorf("protocol %q must be tcp, udp or both (tcp_udp)", s)
}

// Source checks who may use a port forward: "any", or an IPv4 address or
// network. It returns the canonical form ("any", "203.0.113.5" or
// "203.0.113.0/24").
func Source(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "any") {
		return "any", nil
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		return a.String(), nil
	}
	if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() {
		return p.Masked().String(), nil
	}
	return "", fmt.Errorf("source %q must be \"any\", an IPv4 address or a network such as 203.0.113.0/24", s)
}

// wanCount counts the router's WAN connections.
func wanCount(networks []unifi.Network) int {
	n := 0
	for _, net := range networks {
		if net.Purpose == "wan" {
			n++
		}
	}
	return n
}

func interfacesOverlap(a, b string) bool { return a == b || a == "both" || b == "both" }
func protocolsOverlap(a, b string) bool  { return a == b || a == "tcp_udp" || b == "tcp_udp" }

// ProtocolText describes a protocol for people: "TCP", "UDP" or "TCP/UDP".
func ProtocolText(proto string) string {
	switch proto {
	case "tcp":
		return "TCP"
	case "udp":
		return "UDP"
	}
	return "TCP/UDP"
}

// PortForward checks a rule and fills in defaults, in the router's form:
// ForwardPort defaults to Port, Protocol to "tcp_udp", Source to "any" and
// Interface to "wan". It checks what the router doesn't: ranges are
// ascending, ranges and lists are forwarded to the same ports (only a
// single port can be translated), ForwardIP is a host on one of the LANs
// (not the router), the
// WAN exists, the name is unique, and no other enabled rule forwards the
// same port and protocol on the same WAN. others are the existing rules
// (a rule with the same ID as pf is skipped, for updates).
func PortForward(pf *unifi.PortForward, networks []unifi.Network, others []unifi.PortForward) error {
	pf.Name = strings.TrimSpace(pf.Name)
	if pf.Name == "" {
		return fmt.Errorf("a port forward needs a name")
	}
	ports, err := parsePorts(pf.Port)
	if err != nil {
		return err
	}
	pf.Port = strings.ReplaceAll(pf.Port, " ", "")
	if strings.TrimSpace(pf.ForwardPort) == "" {
		pf.ForwardPort = pf.Port
	}
	fwdPorts, err := parsePorts(pf.ForwardPort)
	if err != nil {
		return fmt.Errorf("forward port: %w", err)
	}
	pf.ForwardPort = strings.ReplaceAll(pf.ForwardPort, " ", "")
	// The router only translates a single port; ranges and lists must be
	// forwarded to the same ports.
	if pf.ForwardPort != pf.Port && (portCount(ports) > 1 || portCount(fwdPorts) > 1) {
		return fmt.Errorf("a range or list of ports can only be forwarded to the same ports (%s), not %s; only a single port can be forwarded to a different one", pf.Port, pf.ForwardPort)
	}
	if pf.Protocol, err = NormalizeProtocol(pf.Protocol); err != nil {
		return err
	}
	if pf.Source, err = Source(pf.Source); err != nil {
		return err
	}
	switch pf.Interface {
	case "":
		pf.Interface = "wan"
	case "wan":
	case "wan2", "both":
		if wanCount(networks) < 2 {
			return fmt.Errorf("WAN %q needs a second internet connection, and the router has %d", pf.Interface, wanCount(networks))
		}
	default:
		return fmt.Errorf("WAN %q must be wan, wan2 or both", pf.Interface)
	}
	ip, err := IPv4(pf.ForwardIP)
	if err != nil {
		return fmt.Errorf("forward address: %w", err)
	}
	if _, err := NetworkFor(networks, ip, ""); err != nil {
		return fmt.Errorf("forward address: %w", err)
	}
	pf.ForwardIP = ip.String()

	for _, o := range others {
		if o.ID != "" && o.ID == pf.ID {
			continue
		}
		if strings.EqualFold(o.Name, pf.Name) {
			return fmt.Errorf("a port forward named %q already exists", o.Name)
		}
		if !pf.Enabled || !o.Enabled || !interfacesOverlap(pf.Interface, o.Interface) || !protocolsOverlap(pf.Protocol, o.Protocol) {
			continue
		}
		if op, err := parsePorts(o.Port); err == nil && portsOverlap(ports, op) {
			return fmt.Errorf("port %s %s is already forwarded by %q (port %s to %s)", ProtocolText(pf.Protocol), pf.Port, o.Name, o.Port, o.ForwardIP)
		}
	}
	return nil
}
