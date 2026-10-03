package applianceconsole

import (
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

// Interface describes kernel observations, not a proposed network configuration.
type Interface struct {
	Name      string   `json:"name"`
	Link      string   `json:"link"`
	Addresses []string `json:"addresses"`
}

type kernelInterface struct {
	Name      string          `json:"ifname"`
	State     string          `json:"operstate"`
	Addresses []kernelAddress `json:"addr_info"`
}

type kernelAddress struct {
	Family     string   `json:"family"`
	Local      string   `json:"local"`
	Prefix     *int     `json:"prefixlen"`
	Tentative  bool     `json:"tentative"`
	DADFailed  bool     `json:"dadfailed"`
	Deprecated bool     `json:"deprecated"`
	Flags      []string `json:"flags"`
}

func (a kernelAddress) usable(ip netip.Addr) bool {
	if a.Prefix == nil || *a.Prefix < 0 || *a.Prefix > ip.BitLen() || a.Tentative || a.DADFailed || a.Deprecated {
		return false
	}
	return !slices.Contains(a.Flags, "tentative") && !slices.Contains(a.Flags, "dadfailed") && !slices.Contains(a.Flags, "deprecated")
}

func (c Collector) physicalNIC(name string, depth int) bool {
	if depth > 4 || !interfaceName.MatchString(name) {
		return false
	}
	dir := filepath.Join(c.sources.NetDir, name)
	if _, err := os.Stat(filepath.Join(dir, "device")); err == nil {
		return true
	}
	// VLAN/bond devices may reference a physical interface through lower_*.
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if lower, ok := strings.CutPrefix(entry.Name(), "lower_"); ok && c.physicalNIC(lower, depth+1) {
			return true
		}
	}
	return false
}

func kernelAddresses(nic kernelInterface) (cidrs, addresses []string) {
	for _, a := range nic.Addresses {
		ip, err := netip.ParseAddr(a.Local)
		if err != nil || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
			continue
		}
		if !a.usable(ip) {
			continue
		}
		if (a.Family != "inet" || !ip.Is4()) && (a.Family != "inet6" || !ip.Is6() || ip.Is4In6()) {
			continue
		}
		addresses = append(addresses, ip.String())
		cidrs = append(cidrs, ip.String()+"/"+strconv.Itoa(*a.Prefix))
	}
	slices.Sort(cidrs)
	slices.Sort(addresses)
	return slices.Compact(cidrs), slices.Compact(addresses)
}

func (c Collector) network(raw string) (interfaces []Interface, addresses []string) {
	interfaces, addresses = []Interface{}, []string{}
	var nics []kernelInterface
	if json.Unmarshal([]byte(raw), &nics) != nil {
		return interfaces, addresses
	}
	for i := range nics {
		if !c.physicalNIC(nics[i].Name, 0) {
			continue
		}
		cidrs, ips := kernelAddresses(nics[i])
		interfaces = append(interfaces, Interface{nics[i].Name, Clean(nics[i].State, 16), cidrs})
		addresses = append(addresses, ips...)
	}
	slices.Sort(addresses)
	addresses = slices.Compact(addresses)
	return interfaces, addresses
}

func readPublicFile(path string) string {
	f, err := openPublicFile(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxOutput {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(f, maxOutput+1))
	if err != nil || len(data) > maxOutput {
		return ""
	}
	return string(data)
}

func readHostname(path string) string {
	name := strings.TrimSpace(readPublicFile(path))
	if name == "" {
		return "unknown"
	}
	return Clean(name, 253)
}

func readGateway(raw string) string {
	var routes []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
	}
	if json.Unmarshal([]byte(raw), &routes) != nil {
		return "unknown"
	}
	for _, route := range routes {
		if ip, err := netip.ParseAddr(route.Gateway); err == nil {
			return ip.String() + " (" + Clean(route.Dev, 15) + ")"
		}
	}
	return "unknown"
}

func readDNS(path string) []string {
	addresses := []string{}
	for line := range strings.SplitSeq(readPublicFile(path), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip, err := netip.ParseAddr(fields[1]); err == nil {
			addresses = append(addresses, ip.String())
		}
	}
	return addresses
}
