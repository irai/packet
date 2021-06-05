package internal

import (
	"bytes"
	"net"
	"os"
	"testing"
)

var (
	mac1 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x11}
	mac2 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x22}
	mac3 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x33}
)

func TestNameHandler_LookupMACVendor(t *testing.T) {
	tests := []struct {
		name      string
		wantError bool
		mac       net.HardwareAddr
		result    string
	}{
		{name: "samsung mac", wantError: false, mac: mac1, result: "Samsung Electronics Co.,Ltd"},
		{name: "zero mac", wantError: true, mac: net.HardwareAddr{}, result: ""},
		{name: "nil mac", wantError: true, mac: nil, result: ""},
	}

	// uncomment this
	if checkMAC := os.Getenv("TEST_MAC"); checkMAC == "" {
		t.Log("Skipping mac tests - set TEST_MAC=1 to run tests")
		return
	}

	nameHandler := NewNameHandler("")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nameHandler.findOrCreateIndex(tt.mac)
			vendor, err := nameHandler.LookupMACVendor(tt.mac, 1)
			if vendor != tt.result && err != nil {
				t.Errorf("Error: %s  got <%s> expected %s error %s", tt.name, vendor, tt.result, err)
			}
		})
	}
}

func TestNameHandler_addName(t *testing.T) {
	type args struct {
		mac      net.HardwareAddr
		ip       net.IP
		dhcpName string
		mdnsName string
		nbnsName string
	}
	tests := []struct {
		name      string
		args      args
		wantEntry *NameEntry
	}{
		// TODO: Add test cases.
		{"mac1-dhacp", args{mac: mac1, ip: net.IP{}, dhcpName: "dhcp", mdnsName: "", nbnsName: ""},
			&NameEntry{MAC: mac1, DHCPName: "dhcp", MDNSName: "", NBNSName: ""}},
		{"mac2-mdns", args{mac: mac2, ip: net.IP{}, dhcpName: "", mdnsName: "mdns", nbnsName: ""},
			&NameEntry{MAC: mac2, DHCPName: "", MDNSName: "mdns", NBNSName: ""}},
		{"mac2-nbns", args{mac: mac2, ip: net.IP{}, dhcpName: "", mdnsName: "", nbnsName: "nbns"},
			&NameEntry{MAC: mac2, DHCPName: "", MDNSName: "mdns", NBNSName: "nbns"}},
		{"mac1-entry1.4", args{mac: mac1, ip: net.IP{}, dhcpName: "newdhcp", mdnsName: "mdns", nbnsName: ""},
			&NameEntry{MAC: mac1, DHCPName: "newdhcp", MDNSName: "mdns", NBNSName: ""}},
		{"entry1.5", args{mac: mac1, ip: net.IP{}, dhcpName: "", mdnsName: "newmdns", nbnsName: "nbns2"},
			&NameEntry{MAC: mac1, DHCPName: "newdhcp", MDNSName: "newmdns", NBNSName: "nbns2"}},
		{"entry1.6", args{mac: mac1, ip: net.IP{}, dhcpName: "", mdnsName: "", nbnsName: "newnbns"},
			&NameEntry{MAC: mac1, DHCPName: "newdhcp", MDNSName: "newmdns", NBNSName: "newnbns"}},
		{"mac1-userfinal", args{mac: mac1, ip: net.IP{}, dhcpName: "", mdnsName: "", nbnsName: "newnbns"},
			&NameEntry{MAC: mac1, DHCPName: "newdhcp", MDNSName: "newmdns", NBNSName: "newnbns"}},
		{"mac5-dchp1", args{mac: mac3, ip: net.IP{}, dhcpName: "namedhcp", mdnsName: "", nbnsName: ""},
			&NameEntry{MAC: mac3, DHCPName: "namedhcp", MDNSName: "", NBNSName: ""}},
		{"mac5-dchp-empty", args{mac: mac3, ip: net.IP{}, dhcpName: "EMPTY", mdnsName: "", nbnsName: ""},
			&NameEntry{MAC: mac3, DHCPName: "namedhcp", MDNSName: "", NBNSName: ""}},
	}

	nameHandler := NewNameHandler("")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nameHandler.findOrCreateIndex(tt.args.mac)
			if tt.args.nbnsName != "" {
				nameHandler.SetNBNSName(tt.args.mac, tt.args.nbnsName)
			}
			if tt.args.mdnsName != "" {
				nameHandler.SetMDNSName(tt.args.mac, tt.args.mdnsName, "")
			}
			if tt.args.dhcpName != "" {
				if tt.args.dhcpName == "EMPTY" {
					tt.args.dhcpName = ""
				}
				entry, updated := nameHandler.SetDHCPName(tt.args.mac, tt.args.dhcpName)
				if tt.args.dhcpName == "" && entry.DHCPName == "" {
					t.Errorf("%s: got \n%+v, want \n%+v", tt.name, updated, true)
				}
			}

			i, _, _ := nameHandler.findOrCreateIndex(tt.args.mac)
			gotEntry := nameHandler.nameTable[i]
			if !bytes.Equal(gotEntry.MAC, tt.wantEntry.MAC) ||
				gotEntry.DHCPName != tt.wantEntry.DHCPName ||
				gotEntry.MDNSName != tt.wantEntry.MDNSName ||
				gotEntry.NBNSName != tt.wantEntry.NBNSName {
				t.Errorf("%s: got \n%+v, want \n%+v", tt.name, gotEntry, tt.wantEntry)
				nameHandler.PrintTable()
			}
		})
	}
}

func TestNameHandler_loadNames(t *testing.T) {
	var file1 = []byte(`
- mac:
  - 104
  - 136
  - 197
  - 10
  - 134
  - 196
  name: CAL-2J099034H
  vendor: Intel Corporate
  dhcpname: CAL-2J099034H
  mdnsname: ""
  nbnsname: ""
  osname: ""
  model: ""
  online: false
- mac:
  - 4
  - 236
  - 197
  - 10
  - 134
  - 196
  name: CAL-2J099034H
  vendor: Intel Corporate
  dhcpname: CAL-2J099034H
  mdnsname: ""
  nbnsname: ""
  osname: ""
  model: ""
  online: false
- mac: []
  name: CAL-2J099034H
  vendor: Intel Corporate
  dhcpname: CAL-2J099034H
  mdnsname: ""
  nbnsname: ""
  osname: ""
  model: ""
  online: false
- mac:
  - 0
  - 0
  - 0
  - 0
  - 0
  - 0
  name: ""
  vendor: XEROX CORPORATION
  dhcpname: ""
  mdnsname: ""
  nbnsname: ""
  osname: ""
  model: ""
  online: false
 `)
	tests := []struct {
		name    string
		source  []byte
		wantErr bool
		count   int
	}{
		{"loadNames1", file1, false, 2},
	}

	nameHandler := NewNameHandler("")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := nameHandler.loadNames(tt.source); ((err != nil) != tt.wantErr) ||
				len(nameHandler.nameTable) != tt.count {
				t.Errorf("NameHandler.loadNames() error = %v, count %v, wantCount %v", err, len(nameHandler.nameTable), tt.count)
			}
		})
	}
}
