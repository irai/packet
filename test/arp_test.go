package test

import (
	"net"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	log "github.com/sirupsen/logrus"
)

func TestHandler_arpcapture(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	log.SetLevel(log.DebugLevel)
	dhcp4.Debug = true
	packet.Debug = true
	arp.Debug = true

	// MAC1
	addr := packet.Addr{MAC: MAC1, IP: IP1}
	tests := []TestEvent{
		{name: "capture-" + addr.MAC.String(), hostTableInc: 0, macTableInc: 0, responsePos: 0, responseTableInc: 0,
			action: "capture", srcAddr: packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
			waitTimeAfter: time.Millisecond * 30,
		},
		{name: "arp-announcement-" + addr.MAC.String(),
			action: "arpAnnouncement", hostTableInc: 1, macTableInc: 0, responsePos: -1, responseTableInc: -1,
			srcAddr:       packet.Addr{MAC: addr.MAC, IP: IP1}, // set IP to zero to use savedIP
			wantHost:      &packet.Host{IP: IP1, Online: true},
			waitTimeAfter: time.Millisecond * 10,
		},
	}
	addr = packet.Addr{MAC: MAC2}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}
	checkOnlineCount(t, tc, 3, 0)
	checkCaptureCount(t, tc, 1, 1)
}

// TODO: fix this
/**
func Test_Handler_CaptureEnterOffline(t *testing.T) {
	arp.Debug = true
	packet.Debug = true
	tc := setupTestHandler(t)
	defer tc.Close()

	tests := []struct {
		name    string
		ether   packet.Ether
		arp     ARP
		wantErr error
		wantLen int
	}{
		{name: "replymac2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, routerMAC),
			arp:     newPacket(OperationReply, mac2, ip2, routerMAC, routerIP),
			wantErr: nil, wantLen: 3},
		{name: "replymac3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, routerMAC),
			arp:     newPacket(OperationReply, mac3, ip3, routerMAC, routerIP),
			wantErr: nil, wantLen: 4},
		{name: "replymac4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, routerMAC),
			arp:     newPacket(OperationReply, mac4, ip4, routerMAC, routerIP),
			wantErr: nil, wantLen: 5},
	}

	count := 0
	go func() {
		for {
			select {
			case n := <-tc.session.GetNotificationChannel():
				if n.Online {
					count++
				} else {
					count--
				}
			case <-tc.ctx.Done():
				return
			}
		}
	}()

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

			if len(tc.arp.session.GetHosts()) != tt.wantLen {
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.arp.session.GetHosts()), tt.wantLen)
				tc.arp.session.PrintTable()
			}
		})
	}

	t.Run("cleanup", func(t *testing.T) {
		tc.session.Capture(mac2)

		// wait until offline
		time.Sleep(tc.session.OfflineDeadline * 2)

		// arp request mac2
		ether, _ := tests[0].ether.AppendPayload(tests[0].arp)
		tc.outConn.WriteTo(ether, nil)
		time.Sleep(time.Millisecond * 50)

		log.Printf("notification count=%+v", count)
	})
}

***/
