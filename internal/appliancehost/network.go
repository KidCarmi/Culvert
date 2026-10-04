package appliancehost

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"

	"github.com/goccy/go-yaml"
)

// NetworkRequest deliberately supports one physical IPv4 management interface.
// Complex layouts need an administrator's recovery shell and are never flattened.
type NetworkRequest struct {
	Interface, Mode, Address, Gateway string
	DNS                               []string
	// DHCP6 is observed from the existing configuration, never an operator toggle.
	DHCP6 bool
}

var interfacePattern = regexp.MustCompile(`^(en|eth)[a-zA-Z0-9_-]{1,12}$`)

func usableIPv4(value string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(value)
	return a, err == nil && a.Is4() && a.IsGlobalUnicast() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}

// Candidate validates before serialization; no input becomes shell/YAML syntax.
func Candidate(r NetworkRequest) (File, error) {
	if !interfacePattern.MatchString(r.Interface) {
		return File{}, errors.New("select an explicit physical en*/eth* interface")
	}
	if r.Mode != "dhcp" && r.Mode != "static" {
		return File{}, errors.New("mode must be dhcp or static")
	}
	nic := map[string]any{"dhcp4": r.Mode == "dhcp", "dhcp6": r.DHCP6}
	if r.Mode == "static" {
		if err := staticFields(r, nic); err != nil {
			return File{}, err
		}
	} else if r.Address != "" || r.Gateway != "" || len(r.DNS) != 0 {
		return File{}, errors.New("DHCP does not accept static fields")
	}
	data, err := yaml.Marshal(map[string]any{"network": map[string]any{"version": 2, "ethernets": map[string]any{r.Interface: nic}}})
	return File{Data: data, Exists: true, Mode: 0o600}, err
}

func staticFields(r NetworkRequest, nic map[string]any) error {
	p, err := netip.ParsePrefix(r.Address)
	if err != nil {
		return errors.New("invalid IPv4 address/prefix")
	}
	a, valid := usableIPv4(p.Addr().String())
	g, goodGateway := usableIPv4(r.Gateway)
	if !valid || p.Bits() < 1 || p.Bits() > 30 || a == p.Masked().Addr() || !goodGateway || a == g || !p.Contains(g) {
		return errors.New("use a usable IPv4 host and gateway in the same /1 through /30 subnet")
	}
	last := p.Masked().Addr().As4()
	v := uint32(last[0])<<24 | uint32(last[1])<<16 | uint32(last[2])<<8 | uint32(last[3])
	v |= uint32(1)<<(32-p.Bits()) - 1
	broadcast := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	if a == broadcast || g == broadcast || g == p.Masked().Addr() {
		return errors.New("network/broadcast addresses cannot be hosts or gateways")
	}
	if err := validateDNS(r.DNS); err != nil {
		return err
	}
	nic["addresses"] = []string{p.String()}
	nic["routes"] = []map[string]string{{"to": "default", "via": g.String()}}
	nic["nameservers"] = map[string]any{"addresses": r.DNS}
	return nil
}

func validateDNS(servers []string) error {
	if len(servers) < 1 || len(servers) > 3 {
		return errors.New("static mode requires one to three explicit IPv4 DNS servers")
	}
	for _, server := range servers {
		if _, ok := usableIPv4(server); !ok {
			return errors.New("invalid IPv4 DNS server")
		}
	}
	return nil
}

func onlyKeys(m map[string]any, keys ...string) bool {
	for key := range m {
		if !slices.Contains(keys, key) {
			return false
		}
	}
	return true
}

// ValidateInput rejects secondary interfaces, virtual devices and base-file
// address/route/DNS lists which Netplan would append to our candidate's lists.
func ValidateInput(data []byte, iface string, base bool) error {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return errors.New("invalid Netplan YAML")
	}
	network, ok := doc["network"].(map[string]any)
	if !ok || !onlyKeys(doc, "network") || !onlyKeys(network, "version", "renderer", "ethernets") {
		return errors.New("unsupported Netplan topology")
	}
	if network["version"] != uint64(2) && network["version"] != int64(2) {
		return errors.New("netplan version must be integer 2")
	}
	if renderer, exists := network["renderer"]; exists && renderer != "networkd" {
		return errors.New("only the networkd renderer is supported")
	}
	eth, ok := network["ethernets"].(map[string]any)
	if !ok || len(eth) != 1 {
		return errors.New("guided changes require exactly one physical interface")
	}
	nic, ok := eth[iface].(map[string]any)
	if !ok {
		return fmt.Errorf("netplan must name selected interface %s directly", iface)
	}
	if !base {
		return validateManaged(nic)
	}
	return validateBase(nic, iface)
}

func validateBase(nic map[string]any, iface string) error {
	if err := validateDHCPFields(nic); err != nil {
		return err
	}
	if !onlyKeys(nic, "dhcp4", "dhcp6", "optional", "match", "set-name") || nic["dhcp4"] != true {
		return errors.New("underlying Netplan file must contain only DHCP defaults")
	}
	if name, exists := nic["set-name"]; exists && name != iface {
		return errors.New("interface rename does not match selected device")
	}
	if match, exists := nic["match"]; exists {
		m, ok := match.(map[string]any)
		if !ok || len(m) != 1 || !onlyKeys(m, "macaddress") {
			return errors.New("only an explicit Ethernet MAC match is supported")
		}
		value, ok := m["macaddress"].(string)
		if !ok {
			return errors.New("MAC match must be a string")
		}
		mac, err := net.ParseMAC(value)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
			return errors.New("invalid unicast Ethernet MAC match")
		}
	}
	return nil
}

func validateDHCPFields(nic map[string]any) error {
	for _, field := range []string{"dhcp4", "dhcp6", "optional"} {
		value, exists := nic[field]
		if !exists {
			continue
		}
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s must be a boolean", field)
		}
	}
	return nil
}

// ExistingDHCP6 extracts the observed DHCPv6 flag without conflating an omitted
// field with an explicit false override. Callers combine validated base and
// managed files using Netplan precedence before creating an IPv4 candidate.
func ExistingDHCP6(data []byte, iface string) (value, present bool, err error) {
	nic, err := selectedInterface(data, iface)
	if err != nil {
		return false, false, err
	}
	raw, present := nic["dhcp6"]
	if !present {
		return false, false, nil
	}
	value, ok := raw.(bool)
	if !ok {
		return false, true, errors.New("dhcp6 must be a boolean")
	}
	return value, true, nil
}

func validateManaged(nic map[string]any) error {
	if !onlyKeys(nic, "dhcp4", "dhcp6", "addresses", "routes", "nameservers") {
		return errors.New("managed file contains unsupported settings")
	}
	if err := validateDHCPFields(nic); err != nil {
		return err
	}
	if addresses, exists := nic["addresses"]; exists {
		list, ok := addresses.([]any)
		if !ok || len(list) != 1 || nic["dhcp4"] == true {
			return errors.New("managed file must use one static IPv4 address or DHCP")
		}
		value, ok := list[0].(string)
		prefix, err := netip.ParsePrefix(value)
		if !ok || err != nil || !prefix.Addr().Is4() {
			return errors.New("managed file contains a non-IPv4 address")
		}
	}
	if routes, exists := nic["routes"]; exists {
		if err := validateManagedRoutes(routes); err != nil {
			return err
		}
	}
	if nameservers, exists := nic["nameservers"]; exists {
		return validateManagedDNS(nameservers)
	}
	return nil
}

func validateManagedRoutes(value any) error {
	list, ok := value.([]any)
	if !ok || len(list) != 1 {
		return errors.New("managed file must have exactly one IPv4 default route")
	}
	route, ok := list[0].(map[string]any)
	if !ok || !onlyKeys(route, "to", "via") {
		return errors.New("managed route contains unsupported settings")
	}
	via, ok := route["via"].(string)
	if _, valid := usableIPv4(via); !ok || !valid {
		return errors.New("managed route gateway must be IPv4")
	}
	if route["to"] != "default" && route["to"] != "0.0.0.0/0" {
		return errors.New("managed route must be an IPv4 default route")
	}
	return nil
}

func validateManagedDNS(value any) error {
	nameservers, ok := value.(map[string]any)
	if !ok || !onlyKeys(nameservers, "addresses") {
		return errors.New("guided changes do not support DNS search or other nameserver settings")
	}
	addresses, ok := nameservers["addresses"].([]any)
	if !ok {
		return errors.New("managed nameserver addresses must be an IPv4 list")
	}
	var servers []string
	for _, address := range addresses {
		server, ok := address.(string)
		if !ok {
			return errors.New("managed nameserver address must be a string")
		}
		servers = append(servers, server)
	}
	return validateDNS(servers)
}

// ValidateHardware binds an optional base-file MAC selector to the actual
// selected interface. Syntax validation alone cannot establish device identity.
func ValidateHardware(data []byte, iface, hardware string) error {
	nic, err := selectedInterface(data, iface)
	if err != nil {
		return err
	}
	match, exists := nic["match"]
	if !exists {
		return nil
	}
	selector, ok := match.(map[string]any)
	if !ok || len(selector) != 1 || !onlyKeys(selector, "macaddress") {
		return errors.New("only an explicit Ethernet MAC match is supported")
	}
	value, ok := selector["macaddress"].(string)
	if !ok {
		return errors.New("MAC match must be a string")
	}
	want, wantErr := net.ParseMAC(value)
	actual, actualErr := net.ParseMAC(hardware)
	if wantErr != nil || actualErr != nil || len(want) != 6 || !bytes.Equal(want, actual) {
		return errors.New("netplan MAC match differs from selected physical interface")
	}
	return nil
}

func selectedInterface(data []byte, iface string) (map[string]any, error) {
	var doc struct {
		Network struct {
			Ethernets map[string]map[string]any `yaml:"ethernets"`
		} `yaml:"network"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, errors.New("invalid Netplan YAML")
	}
	nic, ok := doc.Network.Ethernets[iface]
	if !ok || nic == nil {
		return nil, errors.New("selected interface missing from Netplan")
	}
	return nic, nil
}
