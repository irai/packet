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

func Test_declineSimple(t *testing.T) {
	packet.DebugIP4 = false
	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	srcAddr := packet.Addr{MAC: mac5, IP: net.IPv4zero, Port: packet.DHCP4ClientPort}
	xid := newDHCPHost(t, tc, srcAddr.MAC)
	checkLeaseTable(t, tc, 1, 0, 0)

	dhcpFrame := newDHCP4DeclineFrame(srcAddr, tc.IPOffer, hostIP4, xid)
	dstAddr := packet.Addr{MAC: hostMAC, IP: hostIP4, Port: packet.DHCP4ServerPort}
	sendDHCP4Packet(tc.outConn, srcAddr, dstAddr, dhcpFrame)
	time.Sleep(time.Millisecond * 10)
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
	srcAddr := packet.Addr{MAC: mac5, IP: net.IPv4zero, Port: packet.DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: arp.EthernetBroadcast, IP: net.IPv4zero, Port: packet.DHCP4ServerPort}

	// discover packet
	dhcpFrame := newDHCP4DiscoverFrame(srcAddr, "name1", xid)
	sendDHCP4Packet(tc.outConn, srcAddr, dstAddr, dhcpFrame)
	time.Sleep(time.Millisecond * 10)
	checkLeaseTable(t, tc, 0, 1, 0)

	// decline for other host
	dhcpFrame = newDHCP4DeclineFrame(srcAddr, ip5, routerIP4, xid)
	dstAddr = packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ServerPort}
	sendDHCP4Packet(tc.outConn, srcAddr, dstAddr, dhcpFrame)
	time.Sleep(time.Millisecond * 10)
	checkLeaseTable(t, tc, 0, 1, 0)

	// request for our server
	newDHCPHost(t, tc, srcAddr.MAC)
	time.Sleep(time.Millisecond * 10)
	if len(tc.responseTable) != 3 {
		t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", len(tc.responseTable), 3)
	}
	checkLeaseTable(t, tc, 1, 0, 0)

}
