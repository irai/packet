package icmp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/irai/packet"
)

var (
	ip1 = netip.MustParseAddr("192.168.0.1")
	ip2 = netip.MustParseAddr("192.168.0.2")
	ip3 = netip.MustParseAddr("192.168.0.3")
	ip4 = netip.MustParseAddr("192.168.0.4")
	ip5 = netip.MustParseAddr("192.168.0.5")

	localIP  = netip.MustParseAddr("169.254.0.10")
	localIP2 = netip.MustParseAddr("169.254.0.11")

	hostMAC   = net.HardwareAddr{0x00, 0x55, 0x55, 0x55, 0x55, 0x55}
	hostIP4   = netip.MustParseAddr("192.168.0.129")
	routerMAC = net.HardwareAddr{0x00, 0x66, 0x66, 0x66, 0x66, 0x66}
	routerIP4 = netip.MustParseAddr("192.168.0.11")
	homeLAN   = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 0}), 24)

	mac1    = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2    = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3    = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4    = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5    = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x05}
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

	ip61 = net.IP{0x20, 0x01, 0xff, 0xaa, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip62 = net.IP{0x20, 0x01, 0xff, 0xaa, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	ip63 = net.IP{0x20, 0x01, 0xff, 0xaa, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03}

	ip6LLAHost   = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x10})
	ip6LLARouter = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})
	ip6LLA1      = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})
	ip6LLA2      = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02})
	ip6LLA3      = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03})
	ip6LLA4      = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04})
	ip6LLA5      = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05})

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

func testSession() *packet.Session {
	// fake nicinfo
	nicInfo := &packet.NICInfo{
		HomeLAN4:    homeLAN,
		HostAddr4:   hostAddr,
		RouterAddr4: routerAddr,
	}

	// TODO: fix this to discard writes like ioutil.Discard
	conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")

	session, _ := packet.Config{Conn: conn, NICInfo: nicInfo}.NewSession("")
	return session
}

func setupTestHandler() *testContext {

	var err error

	tc := testContext{}
	tc.ctx, tc.cancel = context.WithCancel(context.Background())
	tc.session = testSession()

	// fake conn
	tc.inConn, tc.outConn = packet.TestNewBufferedConn()
	go packet.TestReadAndDiscardLoop(tc.outConn) // MUST read the out conn to avoid blocking the sender
	tc.session.Conn = tc.inConn

	// tc.inConn, tc.outConn = packet.TestNewBufferedConn()
	// go packet.TestReadAndDiscardLoop(tc.ctx, tc.outConn) // MUST read the out conn to avoid blocking the sender

	// fake nicinfo
	tc.session.NICInfo = &packet.NICInfo{
		HomeLAN4:    homeLAN,
		HostAddr4:   packet.Addr{MAC: hostMAC, IP: hostIP4},
		RouterAddr4: packet.Addr{MAC: routerMAC, IP: routerIP4},
	}

	if tc.h, err = New6(tc.session); err != nil {
		panic(err)
	}

	time.Sleep(time.Millisecond * 10) // time for all goroutine to start
	return &tc
}

func (tc *testContext) Close() {
	time.Sleep(time.Millisecond * 20) // wait for all packets to finish
	if Logger4.IsDebug() {
		fmt.Println("teminating context")
	}
	tc.cancel()
	tc.wg.Wait()
}
