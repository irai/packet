package arp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irai/packet"
)

var (
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

	hostMAC   = net.HardwareAddr{0x00, 0xff, 0x03, 0x04, 0x05, 0x01} // keep first byte zero for unicast mac
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

	addr1 = packet.Addr{MAC: mac1, IP: ip1}
	addr2 = packet.Addr{MAC: mac2, IP: ip2}
	addr3 = packet.Addr{MAC: mac3, IP: ip3}
	addr4 = packet.Addr{MAC: mac4, IP: ip4}
	addr5 = packet.Addr{MAC: mac5, IP: ip5}

	routerAddr = packet.Addr{MAC: routerMAC, IP: routerIP}
	hostAddr   = packet.Addr{MAC: hostMAC, IP: hostIP}
)

func newEtherPacket(hType uint16, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr) packet.Ether {
	buf := make([]byte, packet.EthMaxSize)
	p := packet.EtherMarshalBinary(buf, hType, srcMAC, dstMAC)
	return p
}

func newARPPacket(op uint16, srcAddr packet.Addr, dstAddr packet.Addr) packet.ARP {
	p, err := packet.ARPMarshalBinary(nil, op, srcAddr, dstAddr)
	if err != nil {
		panic(err)
	}
	return p
}

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
		HostAddr4:   packet.Addr{MAC: hostMAC, IP: hostIP},
		RouterAddr4: packet.Addr{MAC: routerMAC, IP: routerIP},
	}

	tc.session, err = packet.Config{Conn: tc.inConn, NICInfo: nicInfo}.NewSession()

	if tc.arp, err = New(tc.session); err != nil {
		t.Fatal(err)
	}

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

		arpFrame := packet.ARP(ether.Payload())
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
	Debug = true
	packet.Debug = true
	tc := setupTestHandler(t)
	defer tc.Close()

	// Addr4 is captured
	tc.arp.huntList[string(addr4.MAC)] = addr4

	tests := []struct {
		name       string
		ether      packet.Ether
		arp        packet.ARP
		wantErr    error
		wantLen    int
		wantResult bool
	}{
		{name: "replymac2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, routerMAC),
			arp:     newARPPacket(packet.OperationReply, addr2, routerAddr),
			wantErr: nil, wantLen: 3, wantResult: true},
		{name: "replymac3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, routerMAC),
			arp:     newARPPacket(packet.OperationReply, addr3, routerAddr),
			wantErr: nil, wantLen: 4, wantResult: true},
		{name: "replymac4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, routerMAC),
			arp:     newARPPacket(packet.OperationReply, addr4, routerAddr),
			wantErr: nil, wantLen: 5, wantResult: true},
		{name: "request",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, routerMAC),
			arp:     newARPPacket(packet.OperationRequest, addr4, routerAddr),
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
