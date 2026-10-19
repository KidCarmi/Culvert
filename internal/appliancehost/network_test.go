package appliancehost

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

func staticRequest() NetworkRequest {
	return NetworkRequest{Interface: "ens160", Mode: "static", Address: "192.0.2.10/24", Gateway: "192.0.2.1", DNS: []string{"192.0.2.53", "198.51.100.53"}}
}

func TestCandidateProducesOneExplicitInterfaceWithoutInputSyntax(t *testing.T) {
	staticWithDHCP6 := staticRequest()
	staticWithDHCP6.DHCP6 = true
	for _, request := range []NetworkRequest{staticRequest(), staticWithDHCP6, {Interface: "eth0", Mode: "dhcp"}, {Interface: "eth0", Mode: "dhcp", DHCP6: true}} {
		file, err := Candidate(request)
		if err != nil {
			t.Fatal(err)
		}
		if !file.Exists || file.Mode != 0o600 {
			t.Fatalf("candidate permissions: %+v", file)
		}
		var doc struct {
			Network struct {
				Version   int `yaml:"version"`
				Ethernets map[string]struct {
					DHCP4       bool     `yaml:"dhcp4"`
					DHCP6       bool     `yaml:"dhcp6"`
					Addresses   []string `yaml:"addresses"`
					Routes      []struct{ To, Via string }
					Nameservers struct{ Addresses []string }
				} `yaml:"ethernets"`
			} `yaml:"network"`
		}
		if err := yaml.Unmarshal(file.Data, &doc); err != nil {
			t.Fatal(err)
		}
		nic, found := doc.Network.Ethernets[request.Interface]
		if !found || doc.Network.Version != 2 || len(doc.Network.Ethernets) != 1 || nic.DHCP6 != request.DHCP6 || nic.DHCP4 != (request.Mode == "dhcp") {
			t.Fatalf("wrong interface configuration: %s", file.Data)
		}
		if request.Mode == "static" && (len(nic.Addresses) != 1 || nic.Addresses[0] != request.Address || len(nic.Routes) != 1 || nic.Routes[0].To != "default" || nic.Routes[0].Via != request.Gateway || len(nic.Nameservers.Addresses) != 2) {
			t.Fatalf("static configuration lost fields: %s", file.Data)
		}
		if err := ValidateInput(file.Data, request.Interface, false); err != nil {
			t.Fatal("generated candidate rejected", err)
		}
	}
}

func TestCandidateRejectsHostGatewayAndInjectionEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		edit func(*NetworkRequest)
	}{
		{"interface syntax", func(r *NetworkRequest) { r.Interface = "ens160\n  bridges:" }},
		{"interface shell", func(r *NetworkRequest) { r.Interface = "eth0;reboot" }},
		{"virtual interface", func(r *NetworkRequest) { r.Interface = "br0" }},
		{"VLAN interface", func(r *NetworkRequest) { r.Interface = "eth0.10" }},
		{"loopback interface", func(r *NetworkRequest) { r.Interface = "lo" }},
		{"long interface", func(r *NetworkRequest) { r.Interface = "ens" + strings.Repeat("1", 20) }},
		{"mode", func(r *NetworkRequest) { r.Mode = "STATIC" }},
		{"address injection", func(r *NetworkRequest) { r.Address = "192.0.2.1/24\nroutes: []" }},
		{"address IPv6", func(r *NetworkRequest) { r.Address = "2001:db8::10/64" }},
		{"address network", func(r *NetworkRequest) { r.Address = "192.0.2.0/24" }},
		{"address broadcast", func(r *NetworkRequest) { r.Address = "192.0.2.255/24" }},
		{"address multicast", func(r *NetworkRequest) { r.Address = "224.0.0.10/24" }},
		{"address loopback", func(r *NetworkRequest) { r.Address = "127.0.0.10/24" }},
		{"address link local", func(r *NetworkRequest) { r.Address = "169.254.1.10/24" }},
		{"prefix zero", func(r *NetworkRequest) { r.Address = "192.0.2.10/0" }},
		{"prefix point to point", func(r *NetworkRequest) { r.Address = "192.0.2.10/31" }},
		{"prefix host route", func(r *NetworkRequest) { r.Address = "192.0.2.10/32" }},
		{"gateway equal host", func(r *NetworkRequest) { r.Gateway = "192.0.2.10" }},
		{"gateway outside subnet", func(r *NetworkRequest) { r.Gateway = "198.51.100.1" }},
		{"gateway network", func(r *NetworkRequest) { r.Gateway = "192.0.2.0" }},
		{"gateway broadcast", func(r *NetworkRequest) { r.Gateway = "192.0.2.255" }},
		{"gateway IPv6", func(r *NetworkRequest) { r.Gateway = "2001:db8::1" }},
		{"gateway injection", func(r *NetworkRequest) { r.Gateway = "192.0.2.1; reboot" }},
		{"DNS missing", func(r *NetworkRequest) { r.DNS = nil }},
		{"DNS too many", func(r *NetworkRequest) { r.DNS = []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"} }},
		{"DNS injection", func(r *NetworkRequest) { r.DNS = []string{"192.0.2.53\nsearch: [bad]"} }},
		{"DNS loopback", func(r *NetworkRequest) { r.DNS = []string{"127.0.0.53"} }},
		{"DNS hostname", func(r *NetworkRequest) { r.DNS = []string{"dns.example.test"} }},
		{"DHCP static fields", func(r *NetworkRequest) { r.Mode = "dhcp" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := staticRequest()
			tt.edit(&request)
			if _, err := Candidate(request); err == nil {
				t.Fatalf("unsafe request accepted: %+v", request)
			}
		})
	}
}

func TestCandidateAcceptsUsableSlash30AndPrivateAddresses(t *testing.T) {
	for _, address := range []string{"10.10.10.2/30", "172.16.10.2/30", "192.168.10.2/30"} {
		request := staticRequest()
		request.Address = address
		request.Gateway = strings.TrimSuffix(address, "2/30") + "1"
		if _, err := Candidate(request); err != nil {
			t.Fatalf("valid /30 rejected: %s: %v", address, err)
		}
	}
}

func TestValidateInputRejectsMergedListsAndUnsupportedTopology(t *testing.T) {
	for _, field := range []string{"addresses: [192.0.2.2/24]", "routes: [{to: default, via: 192.0.2.1}]", "nameservers: {addresses: [192.0.2.53]}", "nameservers: {search: [example.test]}", "gateway4: 192.0.2.1", "mtu: 9000", "dhcp4-overrides: {use-routes: false}", "match: {name: 'en*'}", "set-name: eth1", "match: {}", "match: {macaddress: '*'}", "match: {macaddress: 123}"} {
		data := []byte("network:\n  version: 2\n  ethernets:\n    ens160:\n      dhcp4: true\n      " + field + "\n")
		if err := ValidateInput(data, "ens160", true); err == nil {
			t.Errorf("unsafe base accepted: %s", field)
		}
	}
	for _, doc := range []string{
		"not: [valid",
		"network: {version: 2, bridges: {br0: {}}, ethernets: {ens160: {dhcp4: true}}}",
		"network: {version: 2, bonds: {bond0: {}}, ethernets: {ens160: {dhcp4: true}}}",
		"network: {version: 2, vlans: {vlan10: {}}, ethernets: {ens160: {dhcp4: true}}}",
		"network: {version: 2, renderer: NetworkManager, ethernets: {ens160: {dhcp4: true}}}",
		"network: {version: 2, ethernets: {ens160: {dhcp4: true}, eth1: {dhcp4: true}}}",
		"network: {version: 2, ethernets: {eth1: {dhcp4: true}}}",
		"network: {ethernets: {ens160: {dhcp4: true}}}",
		"network: {version: 1, ethernets: {ens160: {dhcp4: true}}}",
		"network: {version: '2', ethernets: {ens160: {dhcp4: true}}}",
		"network: {version: 2, ethernets: {ens160: {dhcp4: false}}}",
	} {
		if err := ValidateInput([]byte(doc), "ens160", true); err == nil {
			t.Errorf("unsafe document accepted: %s", doc)
		}
	}
}

func TestValidateInputAcceptsOnlySupportedDHCPBase(t *testing.T) {
	for _, extra := range []string{"", "      dhcp6: true\n", "      dhcp6: false\n", "      optional: true\n", "      match: {macaddress: '00:50:56:12:34:56'}\n      set-name: ens160\n"} {
		doc := "network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    ens160:\n      dhcp4: true\n" + extra
		if err := ValidateInput([]byte(doc), "ens160", true); err != nil {
			t.Fatalf("supported base rejected: %s: %v", doc, err)
		}
	}
}

func TestValidateHardwareBindsMACSelectorToSelectedDevice(t *testing.T) {
	for _, tt := range []struct {
		name, match, hardware string
		valid                 bool
	}{
		{"same address", "{macaddress: '00:50:56:AB:CD:EF'}", "00:50:56:ab:cd:ef", true},
		{"same bytes alternate encoding", "{macaddress: '0050.56ab.cdef'}", "00:50:56:ab:cd:ef", true},
		{"different NIC", "{macaddress: '00:50:56:12:34:56'}", "00:50:56:ab:cd:ef", false},
		{"non-string selector", "{macaddress: 123}", "00:50:56:ab:cd:ef", false},
		{"no selector", "", "00:50:56:ab:cd:ef", true},
		{"empty selector", "{}", "00:50:56:ab:cd:ef", false},
		{"wildcard selector", "{macaddress: '00:50:56:*'}", "00:50:56:ab:cd:ef", false},
		{"wildcard name", "{name: 'en*'}", "00:50:56:ab:cd:ef", false},
		{"unknown physical address", "{macaddress: '00:50:56:ab:cd:ef'}", "", false},
		{"non-Ethernet hardware", "{macaddress: '00:50:56:ab:cd:ef:12:34'}", "00:50:56:ab:cd:ef:12:34", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := "network:\n  version: 2\n  ethernets:\n    ens160:\n      dhcp4: true\n"
			if tt.match != "" {
				doc += "      match: " + tt.match + "\n"
			}
			err := ValidateHardware([]byte(doc), "ens160", tt.hardware)
			if (err == nil) != tt.valid {
				t.Fatalf("hardware result: %v", err)
			}
		})
	}
	for _, doc := range []string{"invalid: [", "network: {ethernets: {eth1: {dhcp4: true}}}"} {
		if err := ValidateHardware([]byte(doc), "ens160", "00:50:56:ab:cd:ef"); err == nil {
			t.Fatal("accepted malformed or wrong-interface input")
		}
	}
}

func TestGuidedIPv4ChangesRejectMalformedBooleans(t *testing.T) {
	for _, base := range []bool{true, false} {
		for _, fields := range []string{"dhcp4: 'true'", "dhcp4: true, dhcp6: 'false'", "dhcp4: true, dhcp6: 1", "dhcp4: true, dhcp6: null", "dhcp4: true, optional: 'true'"} {
			doc := "network: {version: 2, ethernets: {ens160: {" + fields + "}}}"
			if err := ValidateInput([]byte(doc), "ens160", base); err == nil {
				t.Errorf("unsafe IPv4-only input accepted (base=%v): %s", base, fields)
			}
		}
	}
}

func TestExistingDHCP6DistinguishesAbsentFromExplicitOverride(t *testing.T) {
	for _, tt := range []struct {
		name, fields   string
		value, present bool
		wantErr        bool
	}{
		{"enabled", "dhcp4: true, dhcp6: true", true, true, false},
		{"disabled", "dhcp4: true, dhcp6: false", false, true, false},
		{"omitted", "dhcp4: true", false, false, false},
		{"string", "dhcp6: 'true'", false, true, true},
		{"integer", "dhcp6: 1", false, true, true},
		{"null", "dhcp6: null", false, true, true},
		{"sequence", "dhcp6: [true]", false, true, true},
		{"map", "dhcp6: {value: true}", false, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := "network: {version: 2, ethernets: {ens160: {" + tt.fields + "}}}"
			value, present, err := ExistingDHCP6([]byte(doc), "ens160")
			if value != tt.value || present != tt.present || (err != nil) != tt.wantErr {
				t.Fatalf("got value=%v present=%v err=%v", value, present, err)
			}
		})
	}
	for _, doc := range []string{"bad: [", "network: {ethernets: {eth1: {dhcp6: true}}}", "network: {ethernets: {ens160: null}}"} {
		if _, _, err := ExistingDHCP6([]byte(doc), "ens160"); err == nil {
			t.Fatalf("accepted malformed or missing interface: %s", doc)
		}
	}
}

func TestManagedNetworkRefusesToFlattenIPv6OrComplexConfiguration(t *testing.T) {
	for _, fields := range []string{
		"addresses: ['2001:db8::10/64']",
		"addresses: ['192.0.2.10/24', '192.0.2.11/24']",
		"addresses: [{address: '192.0.2.10/24'}]",
		"addresses: [123]",
		"routes: [{to: default, via: '2001:db8::1'}]",
		"routes: [{to: '::/0', via: '192.0.2.1'}]",
		"routes: [{to: '198.51.100.0/24', via: '192.0.2.1'}]",
		"routes: [{to: default, via: '192.0.2.1', metric: 100}]",
		"routes: [{to: default, via: 123}]",
		"routes: []",
		"nameservers: {addresses: ['2001:db8::53']}",
		"nameservers: {addresses: ['192.0.2.53'], search: ['example.test']}",
		"nameservers: {addresses: [123]}",
		"nameservers: {addresses: '192.0.2.53'}",
	} {
		doc := "network: {version: 2, ethernets: {ens160: {dhcp4: false, " + fields + "}}}"
		if err := ValidateInput([]byte(doc), "ens160", false); err == nil {
			t.Errorf("complex managed configuration accepted: %s", fields)
		}
	}
}
