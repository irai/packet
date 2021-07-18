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
	log "github.com/sirupsen/logrus"
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
	session       *packet.Session
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	responseTable [][]byte
	xid           int
	IPOffer       net.IP
	count         int
	sync.Mutex
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

		dhcp4Frame := DHCP4(packet.UDP(packet.IP4(packet.Ether(buf).Payload()).Payload()).Payload())
		options := dhcp4Frame.ParseOptions()
		var reqType MessageType
		if t := options[OptionDHCPMessageType]; len(t) != 1 {
			log.Warn("dhcp4: skiping dhcp packet with len not 1")
			continue
		} else {
			reqType = MessageType(t[0])
		}
		if reqType == Offer {
			ip := dhcp4Frame.YIAddr().To4()
			if ip == nil {
				panic("ip is nil")
			}
			tc.Lock()
			tc.IPOffer = ip
			tc.count++
			tc.Unlock()
		}

		tmp := make([]byte, len(buf))
		copy(tmp, buf)
		tc.responseTable = append(tc.responseTable, tmp)
		// used for debuging - disable to avoid verbose logging
		if true {
			fmt.Printf("received msg n=%d %s\n", len(tc.responseTable), ether)
		}
	}
}

func setupTestHandler() *testContext {

	var err error

	tc := testContext{}
	tc.ctx, tc.cancel = context.WithCancel(context.Background())
	tc.session = packet.NewEmptySession()

	// DHCP server conn
	tc.inConn, tc.outConn = packet.TestNewBufferedConn()
	go readResponse(tc.ctx, &tc) // MUST read the out conn to avoid blocking the sender
	tc.session.Conn = tc.inConn

	// DHCP client conn
	tc.clientInConn, tc.clientOutConn = packet.TestNewBufferedConn()
	go packet.TestReadAndDiscardLoop(tc.ctx, tc.clientOutConn) // must read to avoid blocking

	tc.session.NICInfo = &packet.NICInfo{
		HostMAC:   hostMAC,
		HostIP4:   net.IPNet{IP: hostIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterIP4: net.IPNet{IP: routerIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		HomeLAN4:  homeLAN,
	}

	if Debug {
		fmt.Println("nicinfo: ", tc.session.NICInfo)
	}

	tc.h, err = Config{ClientConn: tc.clientInConn}.New(tc.session, net.IPNet{IP: hostIP4, Mask: net.IPv4Mask(255, 255, 255, 128)}, dnsIP4, testDHCPFilename)
	if err != nil {
		panic("cannot create handler: " + err.Error())
	}
	tc.h.mode = ModeSecondaryServerNice

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

func newDHCP4DeclineFrame(src packet.Addr, declineIP net.IP, serverIP net.IP, xid []byte) DHCP4 {
	options := []Option{}
	options = append(options, Option{Code: OptionServerIdentifier, Value: serverIP.To4()})
	options = append(options, Option{Code: OptionRequestedIPAddress, Value: declineIP.To4()})
	options = append(options, Option{Code: OptionMessage, Value: []byte("netfilter decline")})
	return RequestPacket(Decline, src.MAC, src.IP, xid, false, options)
}

func newDHCP4DiscoverFrame(src packet.Addr, name string, xid []byte) DHCP4 {
	options := []Option{}
	opt := Option{Code: OptionDomainNameServer, Value: []byte{}}
	options = append(options, opt)
	opt = Option{Code: OptionHostName, Value: []byte(name)}
	options = append(options, opt)
	return RequestPacket(Discover, src.MAC, src.IP, xid, false, options)
}

func newDHCP4RequestFrame(src packet.Addr, name string, serverID net.IP, requestedIP net.IP, xid []byte) DHCP4 {
	options := []Option{}
	opt := Option{Code: OptionDomainNameServer, Value: []byte{}}
	options = append(options, opt)
	opt = Option{Code: OptionRequestedIPAddress, Value: requestedIP}
	options = append(options, opt)
	opt = Option{Code: OptionServerIdentifier, Value: serverID}
	options = append(options, opt)
	opt = Option{Code: OptionHostName, Value: []byte(name)}
	options = append(options, opt)
	return RequestPacket(Request, src.MAC, requestedIP, xid, false, options)
}

func checkLeaseTable(t *testing.T, tc *testContext, allocatedCount int, discoverCount int, freeCount int) {
	aCount := 0
	fCount := 0
	dCount := 0
	for _, lease := range tc.h.table {
		if lease.State == StateAllocated {
			aCount++
		}
		if lease.State == StateFree {
			fCount++
		}
		if lease.State == StateDiscover {
			dCount++
		}
	}
	if aCount != allocatedCount {
		t.Errorf("leaseTable invalid allocated lease count want=%d got=%d", allocatedCount, aCount)
	}
	if dCount != discoverCount {
		t.Errorf("leaseTable invalid discover lease count want=%d got=%d", discoverCount, dCount)
	}
	if fCount != freeCount {
		t.Errorf("leaseTable invalid free lease count want=%d got=%d", freeCount, fCount)
	}
}

func processTestDHCP4Packet(t *testing.T, tc *testContext, srcAddr packet.Addr, dstAddr packet.Addr, p DHCP4) (result packet.Result, err error) {
	ether := packet.Ether(make([]byte, packet.EthMaxSize))
	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, srcAddr.MAC, dstAddr.MAC)
	ip4 := packet.IP4MarshalBinary(ether.Payload(), 50, srcAddr.IP, dstAddr.IP)
	udp := packet.UDPMarshalBinary(ip4.Payload(), srcAddr.Port, dstAddr.Port)
	udp, err = udp.AppendPayload(p)
	if err != nil {
		return result, err
	}
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)

	if ether, err = ether.SetPayload(ip4); err != nil {
		return result, err
	}

	udp, _ = udp.AppendPayload(p)
	result, err = tc.h.ProcessPacket(nil, ether, udp.Payload())
	if err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	return result, nil
}
