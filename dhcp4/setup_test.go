package dhcp4

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
)

var (
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	ip1     = net.IPv4(192, 168, 0, 1)
	ip2     = net.IPv4(192, 168, 0, 2)
	ip3     = net.IPv4(192, 168, 0, 3)
	ip4     = net.IPv4(192, 168, 0, 4)
	ip5     = net.IPv4(192, 168, 0, 5)

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

	hostAddr   = packet.Addr{MAC: hostMAC, IP: hostIP4}
	routerAddr = packet.Addr{MAC: routerMAC, IP: routerIP4}

	dnsIP4 = net.IPv4(8, 8, 8, 8)
)

type testContext struct {
	inConn        net.PacketConn
	outConn       net.PacketConn
	clientInConn  net.PacketConn
	clientOutConn net.PacketConn
	h             *Handler
	packet        *packet.Handler
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	responseTable [][]byte
}

func readResponse(ctx context.Context, tc *testContext) error {
	buf := make([]byte, 2000)
	for {
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
		if !ether.IsValid() {
			s := fmt.Sprintf("error ether client packet %s", ether)
			panic(s)
		}

		// used for debuging - disable to avoid verbose logging
		if false {
			fmt.Printf("raw: got buffere msg=%s\n", ether)
		}
		tmp := make([]byte, len(buf))
		copy(tmp, buf)
		tc.responseTable = append(tc.responseTable, tmp)
	}
}

func setupTestHandler() *testContext {

	var err error

	tc := testContext{}
	tc.ctx, tc.cancel = context.WithCancel(context.Background())

	tc.inConn, tc.outConn = packet.TestNewBufferedConn()
	go readResponse(tc.ctx, &tc) // MUST read the out conn to avoid blocking the sender

	tc.clientInConn, tc.clientOutConn = packet.TestNewBufferedConn()
	go packet.TestReadAndDiscardLoop(tc.ctx, tc.clientOutConn) // must read to avoid blocking

	nicInfo := packet.NICInfo{
		HostMAC:   hostMAC,
		HostIP4:   net.IPNet{IP: hostIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterIP4: net.IPNet{IP: routerIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
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

	// Default dhcp engine
	netfilterIP, err := packet.SegmentLAN("eth0",
		net.IPNet{IP: hostIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		net.IPNet{IP: routerIP4, Mask: net.IPv4Mask(255, 255, 255, 0)})
	if err != nil {
		panic(err)
	}
	tc.h, err = Config{ClientConn: tc.clientInConn}.Attach(tc.packet, net.IPNet{IP: netfilterIP.IP, Mask: net.IPv4Mask(255, 255, 255, 0)}, dnsIP4, testDHCPFilename)
	if err != nil {
		panic("cannot create handler" + err.Error())
	}
	tc.h.mode = ModeSecondaryServerNice

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

type testEvent struct {
	name          string
	action        string // capture, block, accept, release, event
	packetEvent   packet.Notification
	waitTimeAfter time.Duration
	wantCapture   bool
	wantStage     packet.HuntStage
	wantOnline    bool
	hostTableLen  int
	macTableLen   int
	srcAddr       packet.Addr
	dstAddr       packet.Addr
	ether         packet.Ether
	wantHost      packet.Host
}

func newDHCP4DiscoverFrame(src packet.Addr) packet.Ether {
	options := []Option{}
	oDNS := Option{Code: OptionDomainNameServer, Value: []byte{}}

	var err error
	ether := packet.Ether(make([]byte, packet.EthMaxSize))
	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, src.MAC, arp.EthernetBroadcast)
	ip4 := packet.IP4MarshalBinary(ether.Payload(), 50, src.IP, net.IPv4zero)
	udp := packet.UDPMarshalBinary(ip4.Payload(), packet.DHCP4ClientPort, packet.DHCP4ServerPort)
	dhcp4Frame := RequestPacket(Discover, src.MAC, src.IP, src.MAC, false, append(options, oDNS))
	udp, err = udp.AppendPayload(dhcp4Frame)
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
	if ether, err = ether.SetPayload(ip4); err != nil {
		panic(err.Error())
	}
	return ether
}

var mac1Packets = []testEvent{
	{name: "discover-mac1", action: "dhcp4Discover", hostTableLen: 0, macTableLen: 1,
		ether:         newDHCP4DiscoverFrame(packet.Addr{MAC: mac1, IP: net.IPv4zero}),
		wantHost:      packet.Host{}, // don't want host
		waitTimeAfter: time.Millisecond * 10,
	},
	{name: "discover-mac1-2", action: "dhcp4Discover", hostTableLen: 0, macTableLen: 1,
		ether:         newDHCP4DiscoverFrame(packet.Addr{MAC: mac1, IP: net.IPv4zero}),
		wantHost:      packet.Host{}, // don't want host
		waitTimeAfter: time.Millisecond * 10,
	},
	{name: "discover-mac2", action: "dhcp4Discover", hostTableLen: 0, macTableLen: 2,
		ether:         newDHCP4DiscoverFrame(packet.Addr{MAC: mac2, IP: net.IPv4zero}),
		wantHost:      packet.Host{}, // don't want host
		waitTimeAfter: time.Millisecond * 10,
	},
}

func TestHandler_newHost(t *testing.T) {
	tc := setupTestHandler()
	defer tc.Close()

	packet.Debug = true
	Debug = true

	tests := mac1Packets

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}

}

var buf = make([]byte, packet.EthMaxSize)

func runAction(t *testing.T, tc *testContext, tt testEvent) {

	if _, err := tc.outConn.WriteTo(tt.ether, &packet.Addr{MAC: tt.ether.Dst()}); err != nil {
		panic(err.Error())
	}
	time.Sleep(tt.waitTimeAfter)

	if n := len(tc.packet.LANHosts.Table); n != tt.hostTableLen {
		t.Errorf("%s: invalid host table len want=%v got=%v", tt.name, tt.hostTableLen, n)
		tc.packet.PrintTable()
	}
	if n := len(tc.packet.MACTable.Table); n != tt.macTableLen {
		t.Errorf("%s: invalid host table len want=%v got=%v", tt.name, tt.macTableLen, n)
	}

	switch tt.action {
	case "capture":
		// if _, err := tc.packet.Capture(src.MAC); err != nil {
		// t.Errorf("runEvents() error in DoCapture: %v", err)
		// return
		// }

	case "release":

	case "dhcp4Discover":
		buf := tc.responseTable[len(tc.responseTable)-1]
		ip4Frame := DHCP4(packet.UDP(packet.IP4(packet.Ether(buf).Payload()).Payload()).Payload())
		ip := ip4Frame.YIAddr().To4()
		if ip == nil {
			panic("ip is nil")
		}
		fmt.Println("offer ip=", ip)

	default:
		fmt.Println("invalid action")
	}

	if tt.wantHost.IP != nil {
		// validate host entry
	}

}
