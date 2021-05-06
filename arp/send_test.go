package arp

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/irai/packet"
)

func Test_Handler_ARPRequests(t *testing.T) {
	// packet.Debug = true
	// Debug = true
	// log.SetLevel(log.DebugLevel)
	tc := setupTestHandler(t)
	defer tc.Close()

	packet.Debug = true

	tests := []struct {
		name              string
		ether             packet.Ether
		arp               ARP
		wantErr           error
		wantLen           int
		wantIPs           int
		wantCountResponse int
	}{
		{name: "whois1",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, EthernetBroadcast, ip3),
			wantErr: nil, wantLen: 1, wantIPs: 1, wantCountResponse: 0},
		{name: "whois1-dup2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, EthernetBroadcast, ip3),
			wantErr: nil, wantLen: 1, wantIPs: 1},
		{name: "whois1-dup3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, EthernetBroadcast, ip3),
			wantErr: nil, wantLen: 1, wantIPs: 1},
		{name: "whois2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac3, ip3, EthernetBroadcast, routerIP),
			wantErr: nil, wantLen: 2, wantIPs: 1},
		{name: "announce-ip4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac4, ip4, EthernetBroadcast, ip4),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "host-whois-ip3", // will include host mac - we don't care at the ARP level
			ether:   newEtherPacket(syscall.ETH_P_ARP, hostMAC, EthernetBroadcast),
			arp:     newPacket(OperationRequest, hostMAC, hostIP, EthernetBroadcast, ip3),
			wantErr: nil, wantLen: 4, wantIPs: 0},
		{name: "router-whois-ip3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, routerMAC, EthernetBroadcast),
			arp:     newPacket(OperationRequest, routerMAC, routerIP, EthernetBroadcast, ip3),
			wantErr: nil, wantLen: 5, wantIPs: 0},
		{name: "probe", // probe does not add host but will send a probe reject if IP is not our DHCP IP
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac5, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac5, net.IPv4zero.To4(), zeroMAC, ip5),
			wantErr: nil, wantLen: 5, wantIPs: 0, wantCountResponse: 1},
		{name: "localink",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, localIP, EthernetBroadcast, localIP2),
			wantErr: nil, wantLen: 5, wantIPs: 0, wantCountResponse: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}
			// fmt.Println("frame ether: ", ether, "frame arp: ", ARP(ether.Payload()), "srcarp: ", tt.arp)
			_, result, err := tc.arp.ProcessPacket(nil, ether, ether.Payload())
			if err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			if result.Update {
				tc.session.FindOrCreateHost(result.Addr.MAC, result.Addr.IP)
			}
			time.Sleep(time.Millisecond * 3)

			tc.arp.arpMutex.Lock() // test deadlock
			defer tc.arp.arpMutex.Unlock()

			if len(tc.session.HostTable.Table) != tt.wantLen {
				tc.session.PrintTable()
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.session.HostTable.Table), tt.wantLen)
			}

			if tc.countResponse != tt.wantCountResponse {
				t.Errorf("Test_Requests:%s invali response count=%v, want=%v", tt.name, tc.countResponse, tt.wantCountResponse)
			}
		})
	}
}

func Test_Handler_ServeReplies(t *testing.T) {
	// Debug = true
	// log.SetLevel(log.DebugLevel)
	tc := setupTestHandler(t)
	defer tc.Close()
	packet.Debug = true

	tests := []struct {
		name    string
		ether   packet.Ether
		arp     ARP
		wantErr error
		wantLen int
		wantIPs int
	}{
		{name: "replyHost",
			ether:   newEtherPacket(syscall.ETH_P_ARP, hostMAC, mac2),
			arp:     newPacket(OperationReply, hostMAC, hostIP, mac2, ip2),
			wantErr: nil, wantLen: 1, wantIPs: 0},
		{name: "replyRouter",
			ether:   newEtherPacket(syscall.ETH_P_ARP, routerMAC, EthernetBroadcast),
			arp:     newPacket(OperationReply, routerMAC, routerIP, mac2, ip2),
			wantErr: nil, wantLen: 2, wantIPs: 0},
		{name: "replyLocalLink",
			ether:   newEtherPacket(syscall.ETH_P_ARP, routerMAC, EthernetBroadcast),
			arp:     newPacket(OperationReply, mac2, localIP, zeroMAC, localIP),
			wantErr: nil, wantLen: 2, wantIPs: 0},
		{name: "replyMAC2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, routerMAC),
			arp:     newPacket(OperationReply, mac2, ip2, routerMAC, routerIP),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "replyMAC2-dup",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, mac1),
			arp:     newPacket(OperationReply, mac2, ip2, routerMAC, routerIP),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "requestMAC2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationRequest, mac2, ip2, hostMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "replyMAC2-dup2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationReply, mac2, ip2, hostMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "replyMAC2-newip",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationReply, mac2, ip3, hostMAC, hostIP),
			wantErr: nil, wantLen: 4, wantIPs: 2},
		{name: "requestMAC3-newip",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac3, ip3, hostMAC, hostIP),
			wantErr: nil, wantLen: 4, wantIPs: 1},
		{name: "replyMAC3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, hostMAC),
			arp:     newPacket(OperationReply, mac3, ip4, hostMAC, hostIP),
			wantErr: nil, wantLen: 5, wantIPs: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}
			_, result, err := tc.arp.ProcessPacket(nil, ether, ether.Payload())
			if err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			if result.Update {
				tc.session.FindOrCreateHost(result.Addr.MAC, result.Addr.IP)
			}
			time.Sleep(time.Millisecond * 3)

			tc.arp.arpMutex.Lock()
			defer tc.arp.arpMutex.Unlock()

			if len(tc.session.HostTable.Table) != tt.wantLen {
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.session.HostTable.Table), tt.wantLen)
			}
		})
	}
}
