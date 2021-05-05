package dhcp4

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/model"
)

func TestDHCPHandler_handleDiscover(t *testing.T) {
	options := []Option{}
	oDNS := Option{Code: OptionDomainNameServer, Value: []byte{}}

	// packet.DebugIP4 = true
	Debug = true
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	tests := []struct {
		name          string
		packet        DHCP4
		wantResponse  bool
		tableLen      int
		responseCount int
		srcAddr       model.Addr
		dstAddr       model.Addr
	}{
		{name: "discover-mac1", wantResponse: true, responseCount: 1,
			packet: RequestPacket(Discover, mac1, ip1, []byte{0x01}, false, append(options, oDNS)), tableLen: 1,
			srcAddr: model.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: model.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac1", wantResponse: true, responseCount: 2,
			packet: RequestPacket(Discover, mac1, ip1, []byte{0x01}, false, append(options, oDNS)), tableLen: 1,
			srcAddr: model.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: model.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac1", wantResponse: true, responseCount: 3,
			packet: RequestPacket(Discover, mac1, ip1, []byte{0x02}, false, append(options, oDNS)), tableLen: 1,
			srcAddr: model.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: model.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac1", wantResponse: true, responseCount: 4,
			packet: RequestPacket(Discover, mac1, ip1, []byte{0x03}, false, append(options, oDNS)), tableLen: 1,
			srcAddr: model.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: model.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac2", wantResponse: true, responseCount: 5,
			packet: RequestPacket(Discover, mac2, ip2, []byte{0x01}, false, append(options, oDNS)), tableLen: 2,
			srcAddr: model.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: model.Addr{MAC: mac2, IP: ip2, Port: packet.DHCP4ServerPort}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sendDHCP4Packet(tc.outConn, tt.srcAddr, tt.dstAddr, tt.packet); err != nil {
				t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
				return
			}
			time.Sleep(time.Millisecond * 10)

			if n := len(tc.h.table); n != tt.tableLen {
				tc.h.printTable()
				t.Errorf("DHCPHandler.handleDiscover() invalid lease table len=%d want=%d", n, tt.tableLen)
			}
			if tt.responseCount != len(tc.responseTable) {
				t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", len(tc.responseTable), tt.responseCount)
			}
		})
	}
	checkLeaseTable(t, tc, 0, 2, 0)
}

func TestDHCPHandler_exhaust(t *testing.T) {
	options := []Option{}
	oDNS := Option{Code: OptionDomainNameServer, Value: []byte{}}

	packet.DebugIP4 = false
	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	tests := []struct {
		name          string
		packet        DHCP4
		wantResponse  bool
		tableLen      int
		responseCount int
		srcAddr       model.Addr
		dstAddr       model.Addr
	}{
		{name: "discover-mac1", wantResponse: true, responseCount: 260,
			packet: RequestPacket(Discover, mac1, ip1, []byte{0x01}, false, append(options, oDNS)), tableLen: 256, // maximum unique macs
			srcAddr: model.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: model.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 260; i++ {
				mac := mac1
				mac[5] = byte(i)
				tt.packet = RequestPacket(Discover, mac, net.IPv4zero, []byte{0x01}, false, append(options, oDNS))
				if err := sendDHCP4Packet(tc.outConn, tt.srcAddr, tt.dstAddr, tt.packet); err != nil {
					t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
					return
				}
				time.Sleep(time.Millisecond * 10)
			}

			if n := len(tc.h.table); n != tt.tableLen {
				tc.h.printTable()
				t.Errorf("DHCPHandler.handleDiscover() invalid lease table len=%d want=%d", n, tt.tableLen)
			}
			if tt.responseCount != len(tc.responseTable) {
				t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", len(tc.responseTable), tt.responseCount)
			}
		})
	}
	checkLeaseTable(t, tc, 0, 256, 0) // there will be 256 mac addresses but only 253 ips :-)
}
