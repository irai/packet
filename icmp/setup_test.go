package icmp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/irai/packet"
)

var (
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	ip1     = net.IPv4(192, 168, 0, 1)
	ip2     = net.IPv4(192, 168, 0, 2)
	ip3     = net.IPv4(192, 168, 0, 3)
	ip4     = net.IPv4(192, 168, 0, 4)
	ip5     = net.IPv4(192, 168, 0, 5)

	ip61 = net.IP{0x20, 0x01, 0xff, 0xaa, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip62 = net.IP{0x20, 0x01, 0xff, 0xaa, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	ip63 = net.IP{0x20, 0x01, 0xff, 0xaa, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03}

	hostMAC   = net.HardwareAddr{0x00, 0x55, 0x55, 0x55, 0x55, 0x55}
	hostIP4   = net.IPv4(192, 168, 0, 129).To4()
	routerMAC = net.HardwareAddr{0x00, 0x66, 0x66, 0x66, 0x66, 0x66}
	routerIP4 = net.IPv4(192, 168, 0, 11).To4()
	homeLAN   = net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}

	mac1 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x05}

	ip6LLARouter = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLAHost   = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x10}
	ip6LLA1      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLA2      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	ip6LLA3      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03}
	ip6LLA4      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04}
	ip6LLA5      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05}

	hostAddr      = packet.Addr{MAC: hostMAC, IP: hostIP4}
	routerAddr    = packet.Addr{MAC: routerMAC, IP: routerIP4}
	routerLLAAddr = packet.Addr{MAC: routerMAC, IP: ip6LLARouter}
)

type testContext struct {
	inConn  net.PacketConn
	outConn net.PacketConn
	h       *Handler6
	session *packet.Session
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

func setupTestHandler() *testContext {

	var err error

	tc := testContext{}
	tc.ctx, tc.cancel = context.WithCancel(context.Background())
	tc.session = packet.NewSession()

	// fake conn
	tc.inConn, tc.outConn = packet.TestNewBufferedConn()
	go packet.TestReadAndDiscardLoop(tc.outConn) // MUST read the out conn to avoid blocking the sender
	// go readResponse(tc.ctx, &tc) // MUST read the out conn to avoid blocking the sender
	tc.session.Conn = tc.inConn

	// tc.inConn, tc.outConn = packet.TestNewBufferedConn()
	// go packet.TestReadAndDiscardLoop(tc.ctx, tc.outConn) // MUST read the out conn to avoid blocking the sender

	// fake nicinfo
	tc.session.NICInfo = &packet.NICInfo{
		HostMAC:   hostMAC,
		HostIP4:   net.IPNet{IP: hostIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterIP4: net.IPNet{IP: routerIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		HomeLAN4:  homeLAN,
	}

	if tc.h, err = New6(tc.session); err != nil {
		panic(err)
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
