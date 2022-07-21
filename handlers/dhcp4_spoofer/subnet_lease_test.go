//go:build !arp
// +build !arp

package dhcp4_spoofer

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
)

const testDHCPFilename = "./testDHCPConfig.yml"

var (
	// test table: add subnet combinations here to test the model
	//
	mac0 = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0x0}
)

func Test_Subnet_Save(t *testing.T) {

	// log.SetLevel(log.DebugLevel)
	// Debug = true
	filename := t.TempDir() + "/dhcpconfig.yaml"

	// delete from previous test
	os.Remove(testDHCPFilename)

	tc := setupTestHandler()
	defer tc.Close()

	checkLeaseTable(t, tc, 0, 0, 0)

	// lease 1
	lease := tc.h.findOrCreate(mac1, mac1, "mac1")
	tc.h.allocIPOffer(lease, netip.Addr{})
	lease.State = StateDiscover

	// lease 2
	lease = tc.h.findOrCreate(mac2, mac2, "mac2")
	lease.Addr.IP = ip2
	lease.State = StateAllocated

	// lease 3
	lease = tc.h.findOrCreate(mac3, mac3, "mac3")
	tc.h.allocIPOffer(lease, netip.Addr{})
	lease.Addr.IP = lease.IPOffer
	// lease.IPOffer = nil
	lease.State = StateAllocated

	// lease 4
	tc.h.findOrCreate(mac4, mac4, "mac4")

	checkLeaseTable(t, tc, 2, 1, 1)

	if err := tc.h.saveConfig(filename); err != nil {
		t.Fatal("cannot save", err)
	}

	net1, net2, leases, err := tc.h.loadConfig(filename)
	if err != nil {
		t.Fatalf("unexpected error in lease file %v", err)
		return
	}

	if net1.LAN.Addr() != tc.h.net1.LAN.Addr() || net1.DHCPServer != tc.h.net1.DHCPServer {
		t.Errorf("unexpected net1 %+v, h.net1 %+v ", net1, tc.h.net1)
	}
	if net2.LAN.Addr() != tc.h.net2.LAN.Addr() || net2.DHCPServer != tc.h.net2.DHCPServer {
		t.Errorf("unexpected net2 %+v", net2)
	}

	if n := len(leases); n != 2 {
		t.Errorf("unexpected leases want=%d got=%v", 2, n)
		fmt.Println(leases)
		tc.h.printTable()
	}

}

func Test_Migration(t *testing.T) {

	tc := setupTestHandler()
	defer tc.Close()
	var err error

	if tc.h.net1, tc.h.net2, tc.h.table, err = tc.h.loadByteArray(testMigrationFile); err != nil {
		// old files will not load because of change to netip package.
		// just return
		// ignore
		// t.Error("error in loading []byte stream ", err)
		return
	}

	if n := len(tc.h.table); n != 2 {
		t.Errorf("invalid len want=%v got=%v", 2, n)
	}

	count := 0
	for _, v := range tc.h.table {
		if v.Addr.IP == netip.AddrFrom4([4]byte{192, 168, 1, 8}) || v.Addr.IP == netip.AddrFrom4([4]byte{192, 168, 1, 7}) {
			count++
		}
	}
	if count != 2 {
		t.Errorf("missing ips ")
		tc.h.printTable()
	}
}

var testMigrationFile = []byte(`
net1:
  lan:
    ip: 192.168.1.0
    mask:
    - 255
    - 255
    - 255
    - 0
  defaultgw: 192.168.1.1
  dhcpserver: 192.168.1.129
  dnsserver: 1.1.1.2
  firstip: 192.168.1.1
  lastip: 192.168.1.254
  duration: 4h0m0s
  stage: 1
net2:
  lan:
    ip: 192.168.1.128
    mask:
    - 255
    - 255
    - 255
    - 128
  defaultgw: 192.168.1.129
  dhcpserver: 192.168.1.129
  dnsserver: 1.1.1.3
  firstip: 192.168.1.129
  lastip: 192.168.1.254
  duration: 4h0m0s
  stage: 3
leases:
- clientid:
  - 1
  - 72
  - 134
  - 232
  - 40
  - 84
  - 48
  state: 2
  addr:
    mac:
    - 72
    - 134
    - 232
    - 40
    - 84
    - 48
    ip: 192.168.1.8
    port: 0
  offerexpiry: 2021-03-29T02:20:12.866955344+11:00
  xid:
  - 177
  - 103
  - 18
  - 87
  name: Windows-Phone
  dhcpexpiry: 2021-03-29T08:20:05.123493088+11:00
- clientid:
  - 1
  - 72
  - 134
  - 232
  - 40
  - 84
  - 48
  state: 2
  addr:
    mac:
    - 72
    - 134
    - 232
    - 40
    - 84
    - 48
    ip: 192.168.1.8
    port: 0
  offerexpiry: 2021-03-29T02:20:12.866955344+11:00
  xid:
  - 177
  - 103
  - 18
  - 87
  name: Windows-Phone (Duplicated)
  dhcpexpiry: 2021-03-29T08:20:05.123493088+11:00
- clientid:
  - 1
  - 72
  - 134
  - 232
  - 40
  - 84
  - 00
  state: 2
  addr:
    mac:
    - 72
    - 134
    - 232
    - 40
    - 84
    - 00
    ip: 192.168.1.7
    port: 0
  offerexpiry: 2021-03-29T02:20:12.866955344+11:00
  xid:
  - 177
  - 103
  - 18
  - 87
  name: Fake client
  dhcpexpiry: 2021-03-29T08:20:05.123493088+11:00
`)
