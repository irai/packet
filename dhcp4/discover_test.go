package dhcp4

import (
	"os"
	"testing"
	"time"

	"github.com/irai/packet"
)

func TestDHCPHandler_handleDiscover(t *testing.T) {
	options := []Option{}
	oDNS := Option{Code: OptionDomainNameServer, Value: []byte{}}

	packet.DebugIP4 = true
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
		srcAddr       packet.Addr
		dstAddr       packet.Addr
	}{
		{name: "discover-mac1", wantResponse: true, responseCount: 1,
			packet: RequestPacket(Discover, mac1, ip1, []byte{0x01}, false, append(options, oDNS)), tableLen: 5,
			srcAddr: packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: packet.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac1", wantResponse: true, responseCount: 2,
			packet: RequestPacket(Discover, mac1, ip1, []byte{0x01}, false, append(options, oDNS)), tableLen: 5,
			srcAddr: packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: packet.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac1", wantResponse: true, responseCount: 3,
			packet: RequestPacket(Discover, mac1, ip1, []byte{0x01}, false, append(options, oDNS)), tableLen: 5,
			srcAddr: packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: packet.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac1", wantResponse: true, responseCount: 4,
			packet: RequestPacket(Discover, mac1, ip1, []byte{0x01}, false, append(options, oDNS)), tableLen: 5,
			srcAddr: packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: packet.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac2", wantResponse: true, responseCount: 5,
			packet: RequestPacket(Discover, mac2, ip2, []byte{0x01}, false, append(options, oDNS)), tableLen: 6,
			srcAddr: packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: packet.Addr{MAC: mac2, IP: ip2, Port: packet.DHCP4ServerPort}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sendPacket(tc.outConn, tt.srcAddr, tt.dstAddr, tt.packet); err != nil {
				t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
				return
			}
			time.Sleep(time.Millisecond * 10)

			if tt.tableLen != len(tc.h.net1.getLeases()) {
				tc.h.net1.printSubnet()
				t.Errorf("DHCPHandler.handleDiscover() invalid table len=%d want=%d", len(tc.h.net1.getLeases()), tt.tableLen)
			}
			if tt.responseCount != len(tc.responseTable) {
				t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", len(tc.responseTable), tt.responseCount)
			}
			/**
			if gotD := tc.h.handleDiscover(tt.packet, opts); !reflect.DeepEqual(gotD, tt.wantD) {
				t.Errorf("DHCPHandler.handleDiscover() = %v, want %v", gotD, tt.wantD)
			}
			**/
		})
	}
}
