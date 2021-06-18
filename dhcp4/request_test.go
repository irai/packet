package dhcp4

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
)

func Test_requestSimple(t *testing.T) {

	log.SetLevel(log.DebugLevel)
	packet.DebugIP4 = false
	packet.Debug = true
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
		{name: "request-mac1", wantResponse: true, responseCount: 258, tableLen: 1, allocatedCount: 1, freeCount: 0, discoverCount: 0,
			srcAddr: packet.Addr{MAC: mac1},
		},
		{name: "request-mac2", wantResponse: true, responseCount: 260, tableLen: 2, allocatedCount: 2, freeCount: 0, discoverCount: 0,
			srcAddr: packet.Addr{MAC: mac2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newDHCPHost(t, tc, tt.srcAddr.MAC)

			if n := len(tc.h.table); n != tt.tableLen {
				tc.h.printTable()
				t.Errorf("DHCPHandler.handleDiscover() invalid lease table len=%d want=%d", n, tt.tableLen)
			}
			time.Sleep(time.Millisecond * 200) // CAUTION: it takes long to get all 260 arp responses
			checkLeaseTable(t, tc, tt.allocatedCount, tt.discoverCount, tt.freeCount)
		})
	}

}

func Test_requestExhaust(t *testing.T) {

	packet.Debug = false
	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	// TODO: fix arp notification for invalid host IPs for host (192.168.0.129) and router (192.168.0.11)
	//       test code is sending incorrect arp notification for both host and router
	exhaustAllIPs(t, tc, mac1)

	time.Sleep(time.Second * 3) // WARNING: it takes about 2 seconds to read all 254 notifications

	// send one last discover
	tc.IPOffer = nil
	tc.xid++
	xid := []byte(fmt.Sprintf("%d", tc.xid))
	mac5 = net.HardwareAddr{0x00, 0xff, 0xaa, 0xbb, 0x05, 0x05} // new mac
	srcAddr := packet.Addr{MAC: mac5, IP: net.IPv4zero, Port: packet.DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: arp.EthernetBroadcast, IP: net.IPv4zero, Port: packet.DHCP4ServerPort}
	dhcpFrame := newDHCP4DiscoverFrame(srcAddr, "onelastname", xid)
	if _, err := processTestDHCP4Packet(t, tc, srcAddr, dstAddr, dhcpFrame); err != nil {
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

	// first discover packet
	dhcpFrame := newDHCP4DiscoverFrame(srcAddr, srcAddr.MAC.String(), xid)
	if _, err := processTestDHCP4Packet(t, tc, srcAddr, dstAddr, dhcpFrame); err != nil {
		t.Errorf("Test_requestAnotherHost() error sending packet error=%s", err)
		return
	}
	time.Sleep(time.Millisecond * 10)
	checkLeaseTable(t, tc, 0, 1, 0)

	// request for another host
	result := packet.Result{}
	var err error
	dhcpFrame = newDHCP4RequestFrame(srcAddr, "host name", routerIP4, ip3, xid)
	if result, err = processTestDHCP4Packet(t, tc, srcAddr, dstAddr, dhcpFrame); err != nil {
		t.Fatalf("Test_requestAnotherHost() error sending packet error=%s", err)
	}
	if !result.IsRouter || !result.Update ||
		result.FrameAddr.IP == nil || result.FrameAddr.MAC == nil ||
		result.HuntStage != packet.StageNoChange ||
		result.Name != "host name" {
		t.Fatalf("Test_requestAnotherHost() invalid update=%v isrouter=%v result=%+v ", result.Update, result.IsRouter, result)
	}
	time.Sleep(time.Millisecond * 10)
	checkLeaseTable(t, tc, 0, 1, 0)

	// request for our server
	newDHCPHost(t, tc, srcAddr.MAC)
	time.Sleep(time.Millisecond * 10)
	checkLeaseTable(t, tc, 1, 0, 0)

	// request for another host
	dhcpFrame = newDHCP4RequestFrame(srcAddr, srcAddr.MAC.String(), routerIP4, ip4, xid)
	if _, err := processTestDHCP4Packet(t, tc, srcAddr, dstAddr, dhcpFrame); err != nil {
		t.Fatalf("Test_requestAnotherHost() error sending packet error=%s", err)
	}
	time.Sleep(time.Millisecond * 10)
	checkLeaseTable(t, tc, 0, 0, 1)
}

func newDHCPHost(t *testing.T, tc *testContext, mac net.HardwareAddr) []byte {
	tc.xid++
	xid := []byte(fmt.Sprintf("%d", tc.xid))
	srcAddr := packet.Addr{MAC: mac, IP: net.IPv4zero, Port: packet.DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: arp.EthernetBroadcast, IP: net.IPv4zero, Port: packet.DHCP4ServerPort}

	dhcpFrame := newDHCP4DiscoverFrame(srcAddr, srcAddr.MAC.String(), xid)
	tc.Lock()
	tc.IPOffer = nil
	tc.Unlock()
	if _, err := processTestDHCP4Packet(t, tc, srcAddr, dstAddr, dhcpFrame); err != nil {
		t.Fatalf("newDHCPHost() error sending packet error=%s", err)
	}
	time.Sleep(time.Millisecond * 10)
	tc.Lock()
	if tc.IPOffer == nil {
		tc.Unlock()
		t.Fatalf("didn't get ip offer, check sleep time")
	}
	tc.Unlock()

	dhcpFrame = newDHCP4RequestFrame(srcAddr, srcAddr.MAC.String(), hostIP4, tc.IPOffer, xid)
	result := packet.Result{}
	var err error
	if result, err = processTestDHCP4Packet(t, tc, srcAddr, dstAddr, dhcpFrame); err != nil {
		t.Fatalf("newDHCPHost() error sending packet error=%s", err)
	}
	wantHuntStage := packet.StageNormal
	if tc.h.session.IsCaptured(mac) {
		wantHuntStage = packet.StageRedirected
	}
	if !result.IsRouter || !result.Update ||
		result.FrameAddr.IP == nil || result.FrameAddr.MAC == nil ||
		result.HuntStage != wantHuntStage ||
		result.Name != srcAddr.MAC.String() {
		t.Fatalf("newDHCPHost() invalid update=%v isrouter=%v result=%+v ", result.Update, result.IsRouter, result)
	}
	time.Sleep(time.Millisecond * 10)

	return xid
}

func exhaustAllIPs(t *testing.T, tc *testContext, mac net.HardwareAddr) {
	for i := 0; i < 254; i++ {
		mac[5] = byte(i)
		newDHCPHost(t, tc, mac)
		time.Sleep(time.Microsecond * 200)
	}
	checkLeaseTable(t, tc, 254, 0, 0)
}
