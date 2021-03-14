package dhcp4

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
)

func Test_requestSimple(t *testing.T) {

	// packet.DebugIP4 = true
	Debug = true
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	tests := []struct {
		name           string
		wantResponse   bool
		tableLen       int
		responseCount  int
		allocatedCount int
		discoverCount  int
		freeCount      int
		srcAddr        packet.Addr
		dstAddr        packet.Addr
	}{
		{name: "request-mac1", wantResponse: true, responseCount: 2, tableLen: 1, allocatedCount: 1, freeCount: 0, discoverCount: 0,
			srcAddr: packet.Addr{MAC: mac1},
		},
		{name: "request-mac2", wantResponse: true, responseCount: 4, tableLen: 2, allocatedCount: 2, freeCount: 0, discoverCount: 0,
			srcAddr: packet.Addr{MAC: mac2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newDHCPHost(t, tc, tt.srcAddr.MAC)
			time.Sleep(time.Millisecond * 10)

			if n := len(tc.h.Table); n != tt.tableLen {
				tc.h.printTable()
				t.Errorf("DHCPHandler.handleDiscover() invalid lease table len=%d want=%d", n, tt.tableLen)
			}
			if tt.responseCount != len(tc.responseTable) {
				t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", len(tc.responseTable), tt.responseCount)
			}
			checkLeaseTable(t, tc, tt.allocatedCount, tt.discoverCount, tt.freeCount)
		})
	}
}

func Test_requestExhaust(t *testing.T) {
	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()
	exhaustAllIPs(t, tc, mac1)

	// send one last discover
	tc.IPOffer = nil
	tc.xid++
	xid := []byte(fmt.Sprintf("%d", tc.xid))
	mac5 = net.HardwareAddr{0x00, 0xff, 0xaa, 0xbb, 0x05, 0x05} // new mac
	srcAddr := packet.Addr{MAC: mac5, IP: net.IPv4zero, Port: packet.DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: arp.EthernetBroadcast, IP: net.IPv4zero, Port: packet.DHCP4ServerPort}
	dhcpFrame := newDHCP4DiscoverFrame(srcAddr, xid)
	if err := sendPacket(tc.outConn, srcAddr, dstAddr, dhcpFrame); err != nil {
		t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
		return
	}
	time.Sleep(time.Millisecond * 10)

	if tc.IPOffer != nil {
		t.Errorf("DHCPHandler.handleDiscover() unexpected IP offer ip=%s", tc.IPOffer)
	}
}

func Test_requestAnotherHost(t *testing.T) {
	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	tc.IPOffer = nil
	tc.xid++
	xid := []byte(fmt.Sprintf("%d", tc.xid))
	mac5 = net.HardwareAddr{0x00, 0xff, 0xaa, 0xbb, 0x05, 0x05} // new mac
	srcAddr := packet.Addr{MAC: mac5, IP: net.IPv4zero, Port: packet.DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: arp.EthernetBroadcast, IP: net.IPv4zero, Port: packet.DHCP4ServerPort}
	dhcpFrame := newDHCP4DiscoverFrame(srcAddr, xid)
	if err := sendPacket(tc.outConn, srcAddr, dstAddr, dhcpFrame); err != nil {
		t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
		return
	}
	time.Sleep(time.Millisecond * 10)
	checkLeaseTable(t, tc, 0, 1, 0)

	// request for another host
	dhcpFrame = newDHCP4RequestFrame(srcAddr, routerIP4, ip3, xid)
	if err := sendPacket(tc.outConn, srcAddr, dstAddr, dhcpFrame); err != nil {
		t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
		return
	}
	time.Sleep(time.Millisecond * 10)
	checkLeaseTable(t, tc, 0, 0, 1)

	// request for our server
	newDHCPHost(t, tc, srcAddr.MAC)
	time.Sleep(time.Millisecond * 10)
	if len(tc.responseTable) != 3 {
		t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", len(tc.responseTable), 3)
	}
	checkLeaseTable(t, tc, 1, 0, 0)

	// request for another host
	dhcpFrame = newDHCP4RequestFrame(srcAddr, routerIP4, ip4, xid)
	if err := sendPacket(tc.outConn, srcAddr, dstAddr, dhcpFrame); err != nil {
		t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
		return
	}
	time.Sleep(time.Millisecond * 10)
	checkLeaseTable(t, tc, 0, 0, 1)
}

func newDHCPHost(t *testing.T, tc *testContext, mac net.HardwareAddr) []byte {
	tc.xid++
	xid := []byte(fmt.Sprintf("%d", tc.xid))
	srcAddr := packet.Addr{MAC: mac, IP: net.IPv4zero, Port: packet.DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: arp.EthernetBroadcast, IP: net.IPv4zero, Port: packet.DHCP4ServerPort}

	dhcpFrame := newDHCP4DiscoverFrame(srcAddr, xid)
	if err := sendPacket(tc.outConn, srcAddr, dstAddr, dhcpFrame); err != nil {
		t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
		return nil
	}
	time.Sleep(time.Millisecond * 10)

	dhcpFrame = newDHCP4RequestFrame(srcAddr, hostIP4, tc.IPOffer, xid)
	if err := sendPacket(tc.outConn, srcAddr, dstAddr, dhcpFrame); err != nil {
		t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
		return nil
	}
	time.Sleep(time.Millisecond * 10)
	return xid
}

func exhaustAllIPs(t *testing.T, tc *testContext, mac net.HardwareAddr) {
	for i := 0; i < 254; i++ {
		mac[5] = byte(i)
		newDHCPHost(t, tc, mac)
	}
	checkLeaseTable(t, tc, 254, 0, 0)
}
