package packet

import (
	"bytes"
	"net"
	"net/netip"
	"syscall"
	"testing"
)

func newEtherPacket(hType uint16, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr) Ether {
	buf := make([]byte, EthMaxSize) // allocate in the stack
	p := EncodeEther(buf, hType, srcMAC, dstMAC)
	return p
}

func newARPPacket(op uint16, srcAddr Addr, dstAddr Addr) ARP {
	b := make([]byte, arpLen)
	p := EncodeARP(b, op, srcAddr, dstAddr)
	if p == nil {
		panic("invalid arp packet")
	}
	return p
}

func TestMarshalUnmarshall(t *testing.T) {
	// marshall
	buf := make([]byte, EthMaxSize) // allocate in the stack
	ether := EncodeEther(buf, syscall.ETH_P_ARP, mac1, mac2)
	arpFrame := EncodeARP(ether.Payload(), OperationRequest, addr1, addr2)
	if arpFrame == nil {
		t.Errorf("error in marshall binary: %v", arpFrame)
	}
	if len(ether) != 14 {
		t.Errorf("invalid ether len=%d", len(ether))
	}
	if len(arpFrame) != 28 {
		t.Errorf("invalid arp len=%d", len(arpFrame))
	}

	// unmarschall
	ether.SetPayload(arpFrame)
	n := len(ether)
	ether = Ether(ether[:n])
	arpFrame = ARP(ether.Payload())
	if err := ether.IsValid(); err != nil {
		t.Errorf("invalid ether=%s", ether)
	}
	if err := arpFrame.IsValid(); err != nil {
		t.Errorf("invalid arp=%s", err)
	}

}

func TestMarshalBinary(t *testing.T) {
	tests := []struct {
		name      string
		wantErr   bool
		proto     uint16
		operation uint16
		srcMAC    net.HardwareAddr
		srcIP     netip.Addr
		dstMAC    net.HardwareAddr
		dstIP     netip.Addr
	}{
		{name: "reply", wantErr: false, proto: syscall.ETH_P_ARP, operation: OperationReply, srcMAC: mac1, srcIP: ip1, dstMAC: mac2, dstIP: ip2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := newARPPacket(tt.operation, Addr{MAC: tt.srcMAC, IP: tt.srcIP}, Addr{MAC: tt.dstMAC, IP: tt.dstIP})

			p := ARP(buf)
			if err := p.IsValid(); err != nil {
				t.Errorf("%s: invalid arp err=%s", tt.name, err)
			}
			if p.Operation() != tt.operation {
				t.Errorf("%s: invalid operation=%d want=%d", tt.name, p.Operation(), tt.operation)
			}
			if !bytes.Equal(p.SrcMAC(), tt.srcMAC) || !bytes.Equal(p.DstMAC(), tt.dstMAC) {
				t.Errorf("%s: invalid srcMAC=%s wantSrcMAC=%s dstMAC=%s wantDstMAC=%s", tt.name, p.SrcMAC(), tt.srcMAC, p.DstMAC(), tt.dstMAC)
			}
			if p.SrcIP() != tt.srcIP || p.DstIP() != tt.dstIP {
				t.Errorf("%s: invalid srcIP=%s wantSrcIP=%s dstIP=%s wantDstIP=%s", tt.name, p.SrcIP(), tt.srcIP, p.DstIP(), tt.dstIP)
			}
		})
	}
}

func Test_Handler_ARPRequests(t *testing.T) {
	session, _ := testSession()

	// Debug = true

	tests := []struct {
		name              string
		ether             Ether
		arp               ARP
		wantErr           error
		wantLen           int
		wantIPs           int
		wantCountResponse int
	}{
		{name: "whois1",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newARPPacket(OperationRequest, addr2, Addr{MAC: EthernetBroadcast, IP: ip3}),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantCountResponse: 0},
		{name: "whois1-dup2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newARPPacket(OperationRequest, addr2, Addr{MAC: EthernetBroadcast, IP: ip3}),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "whois1-dup3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newARPPacket(OperationRequest, addr2, Addr{MAC: EthernetBroadcast, IP: ip3}),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "whois2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, EthernetBroadcast),
			arp:     newARPPacket(OperationRequest, addr3, Addr{MAC: EthernetBroadcast, IP: routerIP4}),
			wantErr: nil, wantLen: 4, wantIPs: 1},
		{name: "announce-ip4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, EthernetBroadcast),
			arp:     newARPPacket(OperationRequest, addr4, Addr{MAC: EthernetBroadcast, IP: ip4}),
			wantErr: nil, wantLen: 5, wantIPs: 1},
		{name: "host-whois-ip3", // host mac - ignore entry
			ether:   newEtherPacket(syscall.ETH_P_ARP, hostMAC, EthernetBroadcast),
			arp:     newARPPacket(OperationRequest, hostAddr, Addr{MAC: EthernetBroadcast, IP: ip3}),
			wantErr: nil, wantLen: 5, wantIPs: 0},
		{name: "router-whois-ip3", // router mac - ignore entry
			ether:   newEtherPacket(syscall.ETH_P_ARP, routerMAC, EthernetBroadcast),
			arp:     newARPPacket(OperationRequest, routerAddr, Addr{MAC: EthernetBroadcast, IP: ip3}),
			wantErr: nil, wantLen: 5, wantIPs: 0},
		{name: "probe", // probe does not add host but will send a probe reject if IP is not our DHCP IP
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac5, EthernetBroadcast),
			arp:     newARPPacket(OperationRequest, Addr{MAC: mac5, IP: IPv4zero}, Addr{MAC: EthernetZero, IP: ip5}),
			wantErr: nil, wantLen: 5, wantIPs: 0, wantCountResponse: 1},
		{name: "localink", // local link IP does not add host
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newARPPacket(OperationRequest, Addr{MAC: mac2, IP: localIP}, Addr{MAC: EthernetBroadcast, IP: localIP2}),
			wantErr: nil, wantLen: 5, wantIPs: 0, wantCountResponse: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}

			// TODO: this test should be moved to Parse
			// if bytes.Equal(SrcMAC(ether), session.NICInfo.HostAddr4.MAC) {
			// return
			// }

			// fmt.Println("frame ether: ", ether, "frame arp: ", ARP(ether.Payload()), "srcarp: ", tt.arp)
			result, err := session.Parse(ether)
			if err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}

			if result.Host != nil {
				result.Host.MACEntry.Row.Lock() // test deadlock
				defer result.Host.MACEntry.Row.Unlock()
			}

			if len(session.HostTable.Table) != tt.wantLen {
				session.PrintTable()
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(session.HostTable.Table), tt.wantLen)
			}

		})
	}
}

func Test_Handler_ServeReplies(t *testing.T) {
	session, _ := testSession()
	// Debug = true

	tests := []struct {
		name    string
		ether   Ether
		arp     ARP
		wantErr error
		wantLen int
		wantIPs int
	}{
		{name: "replyHost",
			ether:   newEtherPacket(syscall.ETH_P_ARP, hostMAC, mac2),
			arp:     newARPPacket(OperationReply, hostAddr, addr2),
			wantErr: nil, wantLen: 2, wantIPs: 0},
		{name: "replyRouter",
			ether:   newEtherPacket(syscall.ETH_P_ARP, routerMAC, EthernetBroadcast),
			arp:     newARPPacket(OperationReply, routerAddr, addr2),
			wantErr: nil, wantLen: 2, wantIPs: 0},
		{name: "replyLocalLink",
			ether:   newEtherPacket(syscall.ETH_P_ARP, routerMAC, EthernetBroadcast),
			arp:     newARPPacket(OperationReply, Addr{MAC: mac2, IP: localIP}, Addr{MAC: EthernetZero, IP: localIP}),
			wantErr: nil, wantLen: 2, wantIPs: 0},
		{name: "replyMAC2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, routerMAC),
			arp:     newARPPacket(OperationReply, addr2, routerAddr),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "replyMAC2-dup",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, mac1),
			arp:     newARPPacket(OperationReply, addr2, routerAddr),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "requestMAC2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newARPPacket(OperationRequest, addr2, hostAddr),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "replyMAC2-dup2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newARPPacket(OperationReply, addr2, hostAddr),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "replyMAC2-newip",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newARPPacket(OperationReply, Addr{MAC: mac2, IP: ip3}, hostAddr),
			wantErr: nil, wantLen: 4, wantIPs: 2},
		{name: "requestMAC3-newip",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, EthernetBroadcast),
			arp:     newARPPacket(OperationRequest, addr3, hostAddr),
			wantErr: nil, wantLen: 4, wantIPs: 1},
		{name: "replyMAC3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, hostMAC),
			arp:     newARPPacket(OperationReply, Addr{MAC: mac3, IP: ip4}, hostAddr),
			wantErr: nil, wantLen: 5, wantIPs: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}
			result, err := session.Parse(ether)
			if err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}

			if result.Host != nil {
				result.Host.MACEntry.Row.Lock() // test deadlock
				defer result.Host.MACEntry.Row.Unlock()
			}

			if len(session.HostTable.Table) != tt.wantLen {
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(session.HostTable.Table), tt.wantLen)
			}
		})
	}
}
