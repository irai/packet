package arp

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irai/packet/raw"
)

type notificationCounter struct {
	onlineCounter  int
	offlineCounter int
}

type testContext struct {
	inConn  net.PacketConn
	outConn net.PacketConn
	arp     *Handler
	packet  *raw.Handler
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

func setupTestHandler(t *testing.T) *testContext {

	var err error

	tc := testContext{}
	tc.ctx, tc.cancel = context.WithCancel(context.Background())

	tc.inConn, tc.outConn = raw.TestNewBufferedConn()
	go raw.TestReadAndDiscardLoop(tc.ctx, tc.outConn) // MUST read the out conn to avoid blocking the sender

	nicInfo := raw.NICInfo{
		HostMAC:   hostMAC,
		HostIP4:   net.IPNet{IP: hostIP, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterIP4: net.IPNet{IP: routerIP, Mask: net.IPv4Mask(255, 255, 255, 0)},
		HomeLAN4:  homeLAN,
	}

	// override handler with conn and nicInfo
	config := raw.Config{Conn: tc.inConn, NICInfo: &nicInfo, ProbeInterval: time.Millisecond * 500, OfflineDeadline: time.Millisecond * 500, PurgeDeadline: time.Second * 2}
	tc.packet, err = config.New("eth0")
	if err != nil {
		panic(err)
	}
	if Debug {
		fmt.Println("nicinfo: ", tc.packet.NICInfo)
	}

	tc.arp, err = New(tc.packet.NICInfo, tc.packet.Conn(), tc.packet.LANHosts)
	tc.arp.virtual = newARPTable() // we want an empty table
	tc.packet.HandlerARP = tc.arp

	go func() {
		if err := tc.packet.ListenAndServe(tc.ctx); err != nil {
			panic(err)
		}
	}()

	time.Sleep(time.Millisecond * 10) // time for all goroutine to start
	return &tc
}

func (tc *testContext) Close() {
	time.Sleep(time.Millisecond * 20) // wait for all packets to finish
	if Debug {
		fmt.Println("teminating context")
	}
	tc.cancel()
	tc.wg.Wait()
}

func Test_Handler_CaptureEnterOffline(t *testing.T) {
	Debug = true
	raw.Debug = true
	tc := setupTestHandler(t)
	defer tc.Close()

	tests := []struct {
		name    string
		ether   raw.Ether
		arp     ARP
		wantErr error
		wantLen int
	}{
		{name: "replymac2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, routerMAC),
			arp:     newPacket(OperationReply, mac2, ip2, routerMAC, routerIP),
			wantErr: nil, wantLen: 1},
		{name: "replymac3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, routerMAC),
			arp:     newPacket(OperationReply, mac3, ip3, routerMAC, routerIP),
			wantErr: nil, wantLen: 2},
		{name: "replymac4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, routerMAC),
			arp:     newPacket(OperationReply, mac4, ip4, routerMAC, routerIP),
			wantErr: nil, wantLen: 3},
	}

	count := 0
	tc.packet.AddCallback(
		func(n raw.Notification) error {
			if n.Online {
				count++
			} else {
				count--
			}
			return nil
		})

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

			tc.arp.LANHosts.Lock()
			defer tc.arp.LANHosts.Unlock()

			if len(tc.arp.LANHosts.Table) != tt.wantLen {
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.arp.LANHosts.Table), tt.wantLen)
			}
		})
	}

	t.Run("cleanup", func(t *testing.T) {
		tc.packet.StartHunt(mac2)
		tc.arp.arpMutex.Lock()
		if e := tc.arp.virtual.findByMAC(mac2); e == nil || e.State != StateHunt {
			t.Fatalf("Test_CaptureEnterOffline entry2 state=%s", e.State)
		}
		tc.arp.arpMutex.Unlock()

		// wait until offline
		time.Sleep(tc.packet.OfflineDeadline * 2)

		tc.arp.arpMutex.Lock()
		if e := tc.arp.virtual.findByMAC(mac2); e != nil {
			t.Fatalf("Test_CaptureEnterOffline is not empty entry=%+v", e)
		}
		tc.arp.arpMutex.Unlock()

		// arp request mac2
		ether, _ := tests[0].ether.AppendPayload(tests[0].arp)
		tc.outConn.WriteTo(ether, nil)
		time.Sleep(time.Millisecond * 50)

		tc.arp.arpMutex.Lock()
		if e := tc.arp.virtual.findByMAC(mac2); e == nil {
			t.Fatalf("Test_CaptureEnterOffline is empty")
		}
		tc.arp.arpMutex.Unlock()

		log.Printf("notification count=%+v", count)
	})
}
