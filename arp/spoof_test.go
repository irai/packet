package arp

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/irai/packet"
)

func Test_Probe_Reject(t *testing.T) {
	tc := setupTestHandler(t)
	defer tc.Close()
	Debug = true
	packet.Debug = true

	tests := []struct {
		name              string
		ether             packet.Ether
		arp               ARP
		hunt              bool
		wantErr           error
		wantLen           int
		wantIPs           int
		wantCountResponse int
	}{
		{name: "replyMAC2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, routerMAC),
			arp:     newPacket(OperationReply, mac2, ip2, routerMAC, routerIP),
			wantErr: nil, wantLen: 1, wantIPs: 1, wantCountResponse: 0, hunt: true},
		{name: "replyMAC3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, hostMAC),
			arp:     newPacket(OperationReply, mac3, ip3, hostMAC, hostIP),
			wantErr: nil, wantLen: 2, wantIPs: 2, wantCountResponse: 2, hunt: true}, // MAC2 will enter capture and send two responses
		{name: "probeMAC2", // probe does not add host but will send a probe reject if IP is not our DHCP IP
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, net.IPv4zero.To4(), zeroMAC, ip2),
			wantErr: nil, wantLen: 2, wantIPs: 2, wantCountResponse: 5, hunt: false},
		{name: "probeMAC3", // probe does not add host but will send a probe reject if IP is not our DHCP IP
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac3, net.IPv4zero.To4(), zeroMAC, ip3),
			wantErr: nil, wantLen: 2, wantIPs: 2, wantCountResponse: 6, hunt: false},
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
			var host *packet.Host
			if result.Update {
				host, _ = tc.session.FindOrCreateHost(result.Addr.MAC, result.Addr.IP)
			}
			time.Sleep(time.Millisecond * 3)

			tc.arp.arpMutex.Lock() // lock to test no dead locks
			if len(tc.session.HostTable.Table) != tt.wantLen {
				t.Fatalf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.session.HostTable.Table), tt.wantLen)
			}
			tc.arp.arpMutex.Unlock()

			if len(tc.session.HostTable.Table) != tt.wantLen {
				t.Fatalf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.session.HostTable.Table), tt.wantLen)
			}

			if tc.countResponse != tt.wantCountResponse {
				t.Errorf("Test_Requests:%s invali response count=%v, want=%v", tt.name, tc.countResponse, tt.wantCountResponse)
			}
			if tt.hunt {
				tc.arp.StartHunt(packet.Addr{MAC: host.MACEntry.MAC, IP: host.MACEntry.IP4})
			}
		})
	}

}
