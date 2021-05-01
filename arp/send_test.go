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
		name    string
		ether   packet.Ether
		arp     ARP
		wantErr error
		wantLen int
		wantIPs int
	}{
		{name: "whois1",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, EthernetBroadcast, ip3),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "whois1-dup2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, EthernetBroadcast, ip3),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "whois1-dup3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, EthernetBroadcast, ip3),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "whois2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac3, ip3, EthernetBroadcast, routerIP),
			wantErr: nil, wantLen: 4, wantIPs: 1},
		{name: "announce-ip4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac4, ip4, EthernetBroadcast, ip4),
			wantErr: nil, wantLen: 5, wantIPs: 1},
		{name: "host-whois-ip3", // will ignore host mac - so don't insert in table
			ether:   newEtherPacket(syscall.ETH_P_ARP, hostMAC, EthernetBroadcast),
			arp:     newPacket(OperationRequest, hostMAC, hostIP, EthernetBroadcast, ip3),
			wantErr: nil, wantLen: 5, wantIPs: 0},
		{name: "router-whois-ip3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, routerMAC, EthernetBroadcast),
			arp:     newPacket(OperationRequest, routerMAC, routerIP, EthernetBroadcast, ip3),
			wantErr: nil, wantLen: 5, wantIPs: 0},
		{name: "probe",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac5, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac5, net.IPv4zero.To4(), zeroMAC, ip5),
			wantErr: nil, wantLen: 5, wantIPs: 0},
		{name: "localink",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, localIP, EthernetBroadcast, localIP2),
			wantErr: nil, wantLen: 5, wantIPs: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}
			// fmt.Println("frame ether: ", ether, "frame arp: ", ARP(ether.Payload()), "srcarp: ", tt.arp)
			if _, err := tc.outConn.WriteTo(ether, nil); err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)

			tc.arp.arpMutex.Lock()
			defer tc.arp.arpMutex.Unlock()

			if len(tc.packet.LANHosts.Table) != tt.wantLen {
				tc.packet.PrintTable()
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.packet.LANHosts.Table), tt.wantLen)
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
			wantErr: nil, wantLen: 2, wantIPs: 0},
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
			if _, err := tc.outConn.WriteTo(ether, nil); err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)

			tc.arp.arpMutex.Lock()
			defer tc.arp.arpMutex.Unlock()

			if len(tc.packet.LANHosts.Table) != tt.wantLen {
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.packet.LANHosts.Table), tt.wantLen)
			}
		})
	}
}

/******
func Test_Handler_CaptureSameIP(t *testing.T) {
	Debug = true
	tc := setupTestHandler(t)
	defer tc.Close()

	packet.Debug = true

	e, _ := tc.arp.table.upsert(StateNormal, mac2, ip2)
	e.Online = true
	tc.arp.ForceIPChange(mac2, true)

	tests := []struct {
		name      string
		ether     packet.Ether
		arp       ARP
		wantErr   error
		wantLen   int
		wantIPs   int
		wantState arpState
	}{
		{name: "requestMAC5",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac5, hostMAC),
			arp:     newPacket(OperationRequest, mac5, ip5, zeroMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateNormal},
		{name: "replyMAC2-1",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationReply, mac2, ip2, zeroMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "replyMAC2-2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationReply, mac2, ip2, zeroMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "replyMAC2-3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationReply, mac2, ip2, zeroMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "replyMAC2-4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, routerMAC),
			arp:     newPacket(OperationReply, mac2, ip2, routerMAC, routerIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "replyMAC2-5",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, mac3),
			arp:     newPacket(OperationReply, mac2, ip2, mac3, ip3),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "requestMAC2-1",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, routerMAC),
			arp:     newPacket(OperationRequest, mac2, ip2, zeroMAC, routerIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "requestMAC2-2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationRequest, mac2, ip2, hostMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "requestMAC2-3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, mac3),
			arp:     newPacket(OperationRequest, mac2, ip2, mac3, ip3),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "announce new IP3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip3, zeroMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 2, wantState: StateNormal},
		{name: "announce old IP2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, zeroMAC, ip2),
			wantErr: nil, wantLen: 3, wantIPs: 2, wantState: StateNormal},
		{name: "announce new IP4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationRequest, mac2, ip4, zeroMAC, ip4),
			wantErr: nil, wantLen: 3, wantIPs: 3, wantState: StateNormal},
		{name: "announce new IP5",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip5, zeroMAC, ip5),
			wantErr: nil, wantLen: 3, wantIPs: 4, wantState: StateNormal},
		{name: "announce old IP2-2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, zeroMAC, ip2),
			wantErr: nil, wantLen: 3, wantIPs: 4, wantState: StateNormal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}
			if _, err := tc.outConn.WriteTo(ether, nil); err != tt.wantErr {
				t.Errorf("Test_catpureSameIP:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			fmt.Println("writing finished")
			time.Sleep(time.Millisecond * 10)

			tc.arp.Lock()
			defer tc.arp.Unlock()

			if len(tc.arp.table.macTable) != tt.wantLen {
				tc.arp.PrintTable()
				t.Errorf("Test_catpureSameIP:%s table len = %v, wantLen %v", tt.name, len(tc.arp.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := tc.arp.table.findByMAC(tt.arp.SrcMAC())
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Errorf("Test_catpureSameIP:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantIPs)
					tc.arp.PrintTable()
				}
				if e.State != tt.wantState {
					t.Errorf("Test_captureSameIP:%s entry state=%s, wantState %v", tt.name, e.State, tt.wantState)

				}
			}
		})
	}
}
***/
