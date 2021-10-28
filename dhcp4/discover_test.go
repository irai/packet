package dhcp4

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/irai/packet"
)

func testRequestPacket(mt MessageType, chAddr net.HardwareAddr, cIAddr net.IP, xId []byte, broadcast bool, options Options) DHCP4 {
	p := make(DHCP4, 1024)
	return Marshall(p, BootRequest, mt, chAddr, cIAddr, net.IPv4zero, xId, broadcast, options, options[OptionParameterRequestList])
}

func TestDHCPHandler_handleDiscover(t *testing.T) {
	options := Options{}
	options[OptionCode(OptionParameterRequestList)] = []byte{byte(OptionDomainNameServer)}

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
		srcAddr       packet.Addr
		dstAddr       packet.Addr
	}{
		{name: "discover-mac1", wantResponse: true, responseCount: 1,
			packet: testRequestPacket(Discover, mac1, ip1, []byte{0x01}, false, options), tableLen: 1,
			srcAddr: packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: packet.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac1", wantResponse: true, responseCount: 2,
			packet: testRequestPacket(Discover, mac1, ip1, []byte{0x01}, false, options), tableLen: 1,
			srcAddr: packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: packet.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac1", wantResponse: true, responseCount: 3,
			packet: testRequestPacket(Discover, mac1, ip1, []byte{0x02}, false, options), tableLen: 1,
			srcAddr: packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: packet.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac1", wantResponse: true, responseCount: 4,
			packet: testRequestPacket(Discover, mac1, ip1, []byte{0x03}, false, options), tableLen: 1,
			srcAddr: packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: packet.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
		{name: "discover-mac2", wantResponse: true, responseCount: 5,
			packet: testRequestPacket(Discover, mac2, ip2, []byte{0x01}, false, options), tableLen: 2,
			srcAddr: packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: packet.Addr{MAC: mac2, IP: ip2, Port: packet.DHCP4ServerPort}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			ether := packet.Ether(make([]byte, packet.EthMaxSize))
			ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, tt.srcAddr.MAC, tt.dstAddr.MAC)
			ip4 := packet.IP4MarshalBinary(ether.Payload(), 50, tt.srcAddr.IP, tt.dstAddr.IP)
			udp := packet.UDPMarshalBinary(ip4.Payload(), tt.srcAddr.Port, tt.dstAddr.Port)
			udp, _ = udp.AppendPayload(tt.packet)
			ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
			if ether, err = ether.SetPayload(ip4); err != nil {
				t.Fatal("error processing packet", err)
				return
			}
			_, err = tc.h.ProcessPacket(nil, ether, udp.Payload())
			if err != nil {
				t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
				return
			}
			select {
			case p := <-tc.notifyReply:
				dhcp := DHCP4(packet.UDP(packet.IP4(packet.Ether(p).Payload()).Payload()).Payload())
				options := dhcp.ParseOptions()
				if options[OptionSubnetMask] == nil || options[OptionRouter] == nil || options[OptionDomainNameServer] == nil {
					t.Fatalf("DHCPHandler.handleDiscover() missing options =%v", err)
				}
			case <-time.After(time.Millisecond * 10):
				t.Fatal("failed to receive reply")
			}

			if n := len(tc.h.table); n != tt.tableLen {
				tc.h.printTable()
				t.Errorf("DHCPHandler.handleDiscover() invalid lease table len=%d want=%d", n, tt.tableLen)
			}
			tc.Lock()
			if tt.responseCount != tc.count {
				t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", tc.count, tt.responseCount)
			}
			tc.Unlock()
		})
	}
	checkLeaseTable(t, tc, 0, 2, 0)
}

func TestDHCPHandler_exhaust(t *testing.T) {
	options := Options{}
	options[OptionCode(OptionParameterRequestList)] = []byte{byte(OptionDomainNameServer)}

	packet.DebugIP4 = false
	packet.Debug = false
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
		srcAddr       packet.Addr
		dstAddr       packet.Addr
	}{
		{name: "discover-mac1", wantResponse: true, responseCount: 260,
			packet: testRequestPacket(Discover, mac1, ip1, []byte{0x01}, false, options), tableLen: 256, // maximum unique macs
			srcAddr: packet.Addr{MAC: routerMAC, IP: routerIP4, Port: packet.DHCP4ClientPort},
			dstAddr: packet.Addr{MAC: mac1, IP: ip1, Port: packet.DHCP4ServerPort}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 260; i++ {
				mac := mac1
				mac[5] = byte(i)
				var err error
				ether := packet.Ether(make([]byte, packet.EthMaxSize))
				ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, tt.srcAddr.MAC, tt.dstAddr.MAC)
				ip4 := packet.IP4MarshalBinary(ether.Payload(), 50, tt.srcAddr.IP, tt.dstAddr.IP)
				udp := packet.UDPMarshalBinary(ip4.Payload(), tt.srcAddr.Port, tt.dstAddr.Port)
				dhcp := Marshall(udp.Payload(), BootRequest, Discover, mac, net.IPv4zero, net.IPv4zero, []byte{0x01}, false, options, options[OptionParameterRequestList])
				udp = udp.SetPayload(dhcp)
				ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
				if ether, err = ether.SetPayload(ip4); err != nil {
					t.Fatal("error processing packet", err)
					return
				}
				_, err = tc.h.ProcessPacket(nil, ether, udp.Payload())
				if err != nil {
					t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
					return
				}
				select {
				case <-tc.notifyReply:
				case <-time.After(time.Millisecond * 10):
					t.Fatal("failed to receive reply")
				}
			}

			if n := len(tc.h.table); n != tt.tableLen {
				tc.h.printTable()
				t.Errorf("DHCPHandler.handleDiscover() invalid lease table len=%d want=%d", n, tt.tableLen)
			}
			tc.Lock()
			if tt.responseCount != tc.count {
				t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", tc.count, tt.responseCount)
			}
			tc.Unlock()
		})
	}
	checkLeaseTable(t, tc, 0, 256, 0)
}
