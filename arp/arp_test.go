package arp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

var (
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

	hostMAC   = net.HardwareAddr{0x00, 0xff, 0x03, 0x04, 0x05, 0x01} // keep first byte zero for unicast mac
	hostIP4   = netip.MustParseAddr("192.168.0.129")
	homeLAN   = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 0}), 24)
	routerMAC = net.HardwareAddr{0x00, 0xff, 0x03, 0x04, 0x05, 0x11} // key first byte zero for unicast mac
	routerIP4 = netip.MustParseAddr("192.168.0.11")
	ip1       = netip.MustParseAddr("192.168.0.1")
	ip2       = netip.MustParseAddr("192.168.0.2")
	ip3       = netip.MustParseAddr("192.168.0.3")
	ip4       = netip.MustParseAddr("192.168.0.4")
	ip5       = netip.MustParseAddr("192.168.0.5")

	localIP  = netip.MustParseAddr("169.254.0.10")
	localIP2 = netip.MustParseAddr("169.254.0.11")

	mac1 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x05}

	addr1 = packet.Addr{MAC: mac1, IP: ip1}
	addr2 = packet.Addr{MAC: mac2, IP: ip2}
	addr3 = packet.Addr{MAC: mac3, IP: ip3}
	addr4 = packet.Addr{MAC: mac4, IP: ip4}
	addr5 = packet.Addr{MAC: mac5, IP: ip5}

	routerAddr = packet.Addr{MAC: routerMAC, IP: routerIP4}
	hostAddr   = packet.Addr{MAC: hostMAC, IP: hostIP4}
)

type testContext struct {
	inConn        net.PacketConn
	outConn       net.PacketConn
	arp           *Handler
	session       *packet.Session
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	countResponse int
	sync.Mutex
}

func setupTestHandler(t *testing.T) *testContext {
	var err error

	tc := testContext{}
	tc.ctx, tc.cancel = context.WithCancel(context.Background())

	// fake conn
	tc.inConn, tc.outConn = packet.TestNewBufferedConn()
	go readResponse(tc.ctx, &tc) // MUST read the out conn to avoid blocking the sender

	// fake nicinfo
	nicInfo := &packet.NICInfo{
		HomeLAN4:    homeLAN,
		HostAddr4:   packet.Addr{MAC: hostMAC, IP: hostIP4},
		RouterAddr4: packet.Addr{MAC: routerMAC, IP: routerIP4},
	}

	tc.session, err = packet.Config{Conn: tc.inConn, NICInfo: nicInfo}.NewSession("")

	if tc.arp, err = New(tc.session); err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Millisecond * 10) // time for all goroutine to start
	return &tc
}

func (tc *testContext) Close() {
	time.Sleep(time.Millisecond * 20) // wait for all packets to finish
	tc.cancel()
	tc.wg.Wait()
}

func readResponse(ctx context.Context, tc *testContext) error {
	buffer := make([]byte, 2000)
	for {
		buf := buffer[:]
		n, _, err := tc.outConn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != context.Canceled {
				panic(err)
			}
		}
		if ctx.Err() == context.Canceled {
			return nil
		}

		buf = buf[:n]
		ether := packet.Ether(buf)
		if err := ether.IsValid(); err != nil {
			s := fmt.Sprintf("error ether client packet %s", ether)
			panic(s)
		}

		// used for debuging - disable to avoid verbose logging
		if false {
			fmt.Printf("test  : got test response=%s\n", ether)
		}

		if ether.EtherType() != syscall.ETH_P_ARP {
			panic("invalid ether type")
		}

		arpFrame := ARP(ether.Payload())
		if arpFrame.IsValid() != nil {
			panic("invalid arp packet")
		}
		tc.Lock()
		tc.countResponse++
		tc.Unlock()
		if false {
			fmt.Printf("test  : got test number=%d response=%s\n", tc.countResponse, arpFrame)
		}

		// tmp := make([]byte, len(buf))
		// copy(tmp, buf)

	}
}

func Test_Handler_BasicTest(t *testing.T) {
	Logger.SetLevel(fastlog.LevelDebug)
	packet.Logger.SetLevel(fastlog.LevelDebug)
	tc := setupTestHandler(t)
	defer tc.Close()

	// Addr4 is captured
	tc.arp.huntList[string(addr4.MAC)] = addr4

	tests := []struct {
		name       string
		ether      packet.Ether
		arp        ARP
		wantErr    error
		wantLen    int
		wantResult bool
	}{
		{name: "replymac2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, routerMAC),
			arp:     newARPPacket(OperationReply, addr2, routerAddr),
			wantErr: nil, wantLen: 3, wantResult: true},
		{name: "replymac3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, routerMAC),
			arp:     newARPPacket(OperationReply, addr3, routerAddr),
			wantErr: nil, wantLen: 4, wantResult: true},
		{name: "replymac4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, routerMAC),
			arp:     newARPPacket(OperationReply, addr4, routerAddr),
			wantErr: nil, wantLen: 5, wantResult: true},
		{name: "request",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, routerMAC),
			arp:     newARPPacket(OperationRequest, addr4, routerAddr),
			wantErr: nil, wantLen: 5, wantResult: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}
			if len(ether) != 60 { // test auto padding in append
				t.Errorf("Test_Requests:%s len = %v", tt.name, len(ether))
			}

			frame, _ := tc.session.Parse(ether)
			err = tc.arp.ProcessPacket(frame)
			if err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}

			if len(tc.arp.session.GetHosts()) != tt.wantLen {
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.arp.session.GetHosts()), tt.wantLen)
				tc.arp.session.PrintTable()
			}
		})
	}
}
