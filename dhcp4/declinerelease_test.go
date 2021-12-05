package dhcp4

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/irai/packet"
)

func Test_declineSimple(t *testing.T) {
	packet.Debug = false
	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	srcAddr := packet.Addr{MAC: mac5, IP: net.IPv4zero, Port: DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: hostMAC, IP: hostIP4, Port: DHCP4ServerPort}
	xid := newDHCPHost(t, tc, srcAddr.MAC)
	checkLeaseTable(t, tc, 1, 0, 0)

	ether := newDHCP4DeclineFrame(srcAddr, dstAddr, tc.IPOffer, hostIP4, xid)
	if _, err := tc.h.ProcessPacket(nil, ether, packet.UDP(packet.IP4(ether.Payload()).Payload()).Payload()); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
		t.Fatal("failed invalid reply")
	case <-time.After(time.Millisecond * 10):
	}
	checkLeaseTable(t, tc, 0, 0, 1)
}
func Test_DeclineFromAnotherServer(t *testing.T) {
	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	tc.IPOffer = nil
	tc.xid++
	xid := []byte(fmt.Sprintf("%d", tc.xid))
	mac5 = net.HardwareAddr{0x00, 0xff, 0xaa, 0xbb, 0x05, 0x05} // new mac
	srcAddr := packet.Addr{MAC: mac5, IP: net.IPv4zero, Port: DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: packet.EthernetBroadcast, IP: net.IPv4zero, Port: DHCP4ServerPort}

	// discover packet
	ether := newDHCP4DiscoverFrame(srcAddr, dstAddr, "name1", xid)
	if _, err := tc.h.ProcessPacket(nil, ether, packet.UDP(packet.IP4(ether.Payload()).Payload()).Payload()); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
	case <-time.After(time.Millisecond * 10):
		t.Fatal("failed invalid reply")
	}
	checkLeaseTable(t, tc, 0, 1, 0)

	// decline for other host
	dstAddr = packet.Addr{MAC: routerMAC, IP: routerIP4, Port: DHCP4ServerPort}
	ether = newDHCP4DeclineFrame(srcAddr, dstAddr, ip5, routerIP4, xid)
	if _, err := tc.h.ProcessPacket(nil, ether, packet.UDP(packet.IP4(ether.Payload()).Payload()).Payload()); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
		t.Fatal("failed to receive reply")
	case <-time.After(time.Millisecond * 10):
	}
	checkLeaseTable(t, tc, 0, 1, 0)

	// request for our server
	newDHCPHost(t, tc, srcAddr.MAC)
	if tc.count != 2 { // count offers
		t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", tc.count, 2)
	}
	checkLeaseTable(t, tc, 1, 0, 0)
}
