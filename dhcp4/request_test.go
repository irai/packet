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

	// log.SetLevel(log.DebugLevel)
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
	ether := newDHCP4DiscoverFrame(srcAddr, dstAddr, "onelastname", xid)
	_, err := tc.h.ProcessPacket(nil, ether, packet.UDP(packet.IP4(ether.Payload()).Payload()).Payload())
	if err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
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
	ether := newDHCP4DiscoverFrame(srcAddr, dstAddr, "host name", xid)
	if _, err := tc.h.ProcessPacket(nil, ether, packet.UDP(packet.IP4(ether.Payload()).Payload()).Payload()); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
	case <-time.After(time.Millisecond * 10):
		t.Fatal("failed to receive reply")
	}
	checkLeaseTable(t, tc, 0, 1, 0)

	// request for another host
	result := packet.Result{}
	var err error
	ether = newDHCP4RequestFrame(srcAddr, dstAddr, "host name", routerIP4, ip3, xid)
	if result, err = tc.h.ProcessPacket(nil, ether, packet.UDP(packet.IP4(ether.Payload()).Payload()).Payload()); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
		t.Fatal("invalid  reply")
	case <-time.After(time.Millisecond * 10):
	}
	if !result.IsRouter || !result.Update ||
		result.FrameAddr.IP == nil || result.FrameAddr.MAC == nil ||
		result.HuntStage != packet.StageNoChange ||
		result.NameEntry.Name != "host name" {
		t.Fatalf("Test_requestAnotherHost() invalid update=%v isrouter=%v result=%+v ", result.Update, result.IsRouter, result)
	}
	checkLeaseTable(t, tc, 0, 1, 0)

	// new discover - captured host
	ether = newDHCP4DiscoverFrame(srcAddr, dstAddr, "host name", xid)
	if _, err := tc.h.ProcessPacket(nil, ether, packet.UDP(packet.IP4(ether.Payload()).Payload()).Payload()); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
	case <-time.After(time.Millisecond * 10):
		t.Fatal("failed to receive reply")
	}
	checkLeaseTable(t, tc, 0, 1, 0)

	// request for another server - captured host
	ether = newDHCP4RequestFrame(srcAddr, dstAddr, "host name", routerIP4, ip3, xid)
	if result, err = tc.h.ProcessPacket(nil, ether, packet.UDP(packet.IP4(ether.Payload()).Payload()).Payload()); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
		t.Fatal("failed to receive reply")
	case <-time.After(time.Millisecond * 10):
	}
	checkLeaseTable(t, tc, 0, 1, 0)
}

func exhaustAllIPs(t *testing.T, tc *testContext, mac net.HardwareAddr) {
	for i := 0; i < 254; i++ {
		mac[5] = byte(i)
		newDHCPHost(t, tc, mac)
		// time.Sleep(time.Microsecond * 200)
	}
	checkLeaseTable(t, tc, 254, 0, 0)
}
