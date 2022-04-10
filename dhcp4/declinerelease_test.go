package dhcp4

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

func Test_declineSimple(t *testing.T) {
	packet.Logger.SetLevel(fastlog.LevelError)
	Logger.SetLevel(fastlog.LevelError)
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	srcAddr := packet.Addr{MAC: mac5, IP: packet.IPv4zero, Port: DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: hostMAC, IP: hostIP4, Port: DHCP4ServerPort}
	xid := newDHCPHost(t, tc, srcAddr.MAC, "host1")
	checkLeaseTable(t, tc, 1, 0, 0)

	ether := newDHCP4DeclineFrame(srcAddr, dstAddr, tc.IPOffer, hostIP4, xid)
	frame, err := tc.session.Parse(ether)
	if err != nil {
		panic(err)
	}
	if err := tc.h.ProcessPacket(frame); err != nil {
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
	Logger.SetLevel(fastlog.LevelError)
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	tc.IPOffer = netip.Addr{}
	tc.xid++
	xid := []byte(fmt.Sprintf("%d", tc.xid))
	mac5 = net.HardwareAddr{0x00, 0xff, 0xaa, 0xbb, 0x05, 0x05} // new mac
	srcAddr := packet.Addr{MAC: mac5, IP: packet.IPv4zero, Port: DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: packet.EthernetBroadcast, IP: packet.IPv4zero, Port: DHCP4ServerPort}

	// discover packet
	ether := newDHCP4DiscoverFrame(srcAddr, "name1", xid)
	frame, err := tc.session.Parse(ether)
	if err != nil {
		panic(err)
	}
	if err := tc.h.ProcessPacket(frame); err != nil {
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
	frame, err = tc.session.Parse(ether)
	if err != nil {
		panic(err)
	}
	if err := tc.h.ProcessPacket(frame); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	select {
	case <-tc.notifyReply:
		t.Fatal("failed to receive reply")
	case <-time.After(time.Millisecond * 10):
	}
	checkLeaseTable(t, tc, 0, 1, 0)

	// request for our server
	newDHCPHost(t, tc, srcAddr.MAC, "host2")
	if tc.count != 2 { // count offers
		t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", tc.count, 2)
	}
	checkLeaseTable(t, tc, 1, 0, 0)
}
