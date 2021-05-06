package dhcp4

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/irai/packet/arp"
	"github.com/irai/packet/model"
)

func Test_declineSimple(t *testing.T) {
	model.Debug = false
	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	srcAddr := model.Addr{MAC: mac5, IP: net.IPv4zero, Port: model.DHCP4ClientPort}
	xid := newDHCPHost(t, tc, srcAddr.MAC)
	checkLeaseTable(t, tc, 1, 0, 0)

	dhcpFrame := newDHCP4DeclineFrame(srcAddr, tc.IPOffer, hostIP4, xid)
	dstAddr := model.Addr{MAC: hostMAC, IP: hostIP4, Port: model.DHCP4ServerPort}
	sendTestDHCP4Packet(t, tc, srcAddr, dstAddr, dhcpFrame)
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
	srcAddr := model.Addr{MAC: mac5, IP: net.IPv4zero, Port: model.DHCP4ClientPort}
	dstAddr := model.Addr{MAC: arp.EthernetBroadcast, IP: net.IPv4zero, Port: model.DHCP4ServerPort}

	// discover packet
	dhcpFrame := newDHCP4DiscoverFrame(srcAddr, "name1", xid)
	sendTestDHCP4Packet(t, tc, srcAddr, dstAddr, dhcpFrame)
	time.Sleep(time.Millisecond * 10)
	checkLeaseTable(t, tc, 0, 1, 0)

	// decline for other host
	dhcpFrame = newDHCP4DeclineFrame(srcAddr, ip5, routerIP4, xid)
	dstAddr = model.Addr{MAC: routerMAC, IP: routerIP4, Port: model.DHCP4ServerPort}
	sendTestDHCP4Packet(t, tc, srcAddr, dstAddr, dhcpFrame)
	time.Sleep(time.Millisecond * 10)
	checkLeaseTable(t, tc, 0, 1, 0)

	// request for our server
	newDHCPHost(t, tc, srcAddr.MAC)
	time.Sleep(time.Millisecond * 10)
	if tc.count != 2 { // count offers
		t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", tc.count, 2)
	}
	checkLeaseTable(t, tc, 1, 0, 0)

}
