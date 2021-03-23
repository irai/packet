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

	"github.com/irai/packet"
)

var (
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

	hostMAC   = net.HardwareAddr{0x00, 0xff, 0x03, 0x04, 0x05, 0x01} // key first byte zero for unicast mac
	hostIP    = net.ParseIP("192.168.0.129").To4()
	homeLAN   = net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}
	routerMAC = net.HardwareAddr{0x00, 0xff, 0x03, 0x04, 0x05, 0x11} // key first byte zero for unicast mac
	routerIP  = net.ParseIP("192.168.0.11").To4()
	ip1       = net.ParseIP("192.168.0.1").To4()
	ip2       = net.ParseIP("192.168.0.2").To4()
	ip3       = net.ParseIP("192.168.0.3").To4()
	ip4       = net.ParseIP("192.168.0.4").To4()
	ip5       = net.ParseIP("192.168.0.5").To4()
	mac1      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x05}
	localIP   = net.IPv4(169, 254, 0, 10).To4()
	localIP2  = net.IPv4(169, 254, 0, 11).To4()
)

type notificationCounter struct {
	onlineCounter  int
	offlineCounter int
}

type testContext struct {
	inConn  net.PacketConn
	outConn net.PacketConn
	arp     *Handler
	packet  *packet.Handler
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

func setupTestHandler(t *testing.T) *testContext {

	var err error

	tc := testContext{}
	tc.ctx, tc.cancel = context.WithCancel(context.Background())

	tc.inConn, tc.outConn = packet.TestNewBufferedConn()
	go packet.TestReadAndDiscardLoop(tc.ctx, tc.outConn) // MUST read the out conn to avoid blocking the sender

	nicInfo := packet.NICInfo{
		HostMAC:   hostMAC,
		HostIP4:   net.IPNet{IP: hostIP, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterIP4: net.IPNet{IP: routerIP, Mask: net.IPv4Mask(255, 255, 255, 0)},
		HomeLAN4:  homeLAN,
	}

	// override handler with conn and nicInfo
	config := packet.Config{Conn: tc.inConn, NICInfo: &nicInfo, ProbeInterval: time.Millisecond * 500, OfflineDeadline: time.Millisecond * 500, PurgeDeadline: time.Second * 2}
	tc.packet, err = config.NewEngine("eth0")
	if err != nil {
		panic(err)
	}
	if Debug {
		fmt.Println("nicinfo: ", tc.packet.NICInfo)
	}

	tc.arp, err = Attach(tc.packet)
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
			wantErr: nil, wantLen: 2},
		{name: "replymac3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, routerMAC),
			arp:     newPacket(OperationReply, mac3, ip3, routerMAC, routerIP),
			wantErr: nil, wantLen: 3},
		{name: "replymac4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, routerMAC),
			arp:     newPacket(OperationReply, mac4, ip4, routerMAC, routerIP),
			wantErr: nil, wantLen: 4},
	}

	count := 0
	go func() {
		for {
			select {
			case n := <-tc.packet.GetNotificationChannel():
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

			if len(tc.arp.engine.GetHosts()) != tt.wantLen {
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.arp.engine.GetHosts()), tt.wantLen)
				tc.arp.engine.PrintTable()
			}
		})
	}

	t.Run("cleanup", func(t *testing.T) {
		tc.packet.Capture(mac2)

		// wait until offline
		time.Sleep(tc.packet.OfflineDeadline * 2)

		// arp request mac2
		ether, _ := tests[0].ether.AppendPayload(tests[0].arp)
		tc.outConn.WriteTo(ether, nil)
		time.Sleep(time.Millisecond * 50)

		log.Printf("notification count=%+v", count)
	})
}
