package dhcp4_spoofer

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irai/packet"
)

var (
	ip1 = netip.MustParseAddr("192.168.0.1")
	ip2 = netip.MustParseAddr("192.168.0.2")
	ip3 = netip.MustParseAddr("192.168.0.3")
	ip4 = netip.MustParseAddr("192.168.0.4")
	ip5 = netip.MustParseAddr("192.168.0.5")

	hostMAC   = net.HardwareAddr{0x00, 0x55, 0x55, 0x55, 0x55, 0x55}
	hostIP4   = netip.MustParseAddr("192.168.0.129")
	routerMAC = net.HardwareAddr{0x00, 0x66, 0x66, 0x66, 0x66, 0x66}
	routerIP4 = netip.MustParseAddr("192.168.0.11")
	homeLAN   = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 0}), 24)

	mac1 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x05}

	hostAddr   = packet.Addr{MAC: hostMAC, IP: hostIP4}
	routerAddr = packet.Addr{MAC: routerMAC, IP: routerIP4}

	dnsIP4 = netip.MustParseAddr("8.8.8.8")

	dhcpDst = packet.Addr{MAC: packet.EthBroadcast, IP: packet.IPv4zero, Port: packet.DHCP4ServerPort}
)

type testContext struct {
	inConn        net.PacketConn
	outConn       net.PacketConn
	clientInConn  net.PacketConn
	clientOutConn net.PacketConn
	h             *Handler
	session       *packet.Session
	wg            sync.WaitGroup
	responseTable [][]byte
	notifyReply   chan []byte
	xid           int
	IPOffer       netip.Addr
	count         int
	sync.Mutex
}

func readResponse(tc *testContext) error {
	buffer := make([]byte, 2000)
	for {
		buf := buffer[:]
		n, _, err := tc.outConn.ReadFrom(buf)
		if err != nil {
			return nil
		}

		buf = buf[:n]
		ether := packet.Ether(buf)
		if err := ether.IsValid(); err != nil {
			s := fmt.Sprintf("error ether client packet %s", ether)
			panic(s)
		}

		dhcp4Frame := packet.DHCP4(packet.UDP(packet.IP4(packet.Ether(buf).Payload()).Payload()).Payload())
		options := dhcp4Frame.ParseOptions()
		var reqType packet.DHCP4MessageType
		if t := options[packet.DHCP4OptionDHCPMessageType]; len(t) != 1 {
			fmt.Println("dhcp4: skiping dhcp packet with len not 1")
			continue
		} else {
			reqType = packet.DHCP4MessageType(t[0])
		}
		if reqType == packet.DHCP4Offer {
			ip := dhcp4Frame.YIAddr()
			if !ip.IsValid() {
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
		if false {
			fmt.Printf("received msg n=%d %s\n", len(tc.responseTable), ether)
		}
		if dhcp4Frame.OpCode() == packet.DHCP4BootReply {
			if len(tc.notifyReply) >= cap(tc.notifyReply) {
				fmt.Println("error notifyChannel full - ignoring reply", len(tc.notifyReply))
				continue
			}
			tc.notifyReply <- tmp
		}
	}
}

func setupTestHandler() *testContext {

	var err error

	tc := testContext{notifyReply: make(chan []byte, 32)}

	// DHCP server conn
	tc.inConn, tc.outConn = packet.TestNewBufferedConn()
	go readResponse(&tc) // MUST read the out conn to avoid blocking the sender

	// DHCP client conn
	tc.clientInConn, tc.clientOutConn = packet.TestNewBufferedConn()
	go packet.TestReadAndDiscardLoop(tc.clientOutConn) // must read to avoid blocking

	// fake nicinfo
	nicInfo := &packet.NICInfo{
		RouterAddr4: routerAddr,
		HostAddr4:   hostAddr,
		HomeLAN4:    homeLAN,
	}

	tc.session, err = packet.Config{Conn: tc.inConn, NICInfo: nicInfo}.NewSession("")

	if Logger.IsInfo() {
		fmt.Println("nicinfo: ", tc.session.NICInfo)
	}

	config := Config{
		NetfilterIP:   netip.PrefixFrom(hostIP4, 25),
		DNSServer:     dnsIP4,
		LeaseFilename: testDHCPFilename,
	}
	tc.h, err = config.New(tc.session)
	// tc.h, err = Config{ClientConn: tc.clientInConn}.New(tc.session, net.IPNet{IP: hostIP4, Mask: net.IPv4Mask(255, 255, 255, 128)}, dnsIP4, testDHCPFilename)
	if err != nil {
		panic("cannot create handler: " + err.Error())
	}
	// tc.h.Start()
	// time.Sleep(time.Millisecond * 10) // time for all goroutine to start
	return &tc
}

func (tc *testContext) Close() {
	time.Sleep(time.Millisecond * 20) // wait for all packets to finish
	if Logger.IsInfo() {
		fmt.Println("teminating context")
	}
	tc.wg.Wait()
}

func newDHCPHost(t *testing.T, tc *testContext, mac net.HardwareAddr, name string) []byte {
	tc.xid++
	xid := []byte(fmt.Sprintf("%d", tc.xid))
	srcAddr := packet.Addr{MAC: mac, IP: packet.IPv4zero, Port: packet.DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: packet.EthernetBroadcast, IP: packet.IPv4zero, Port: packet.DHCP4ServerPort}

	tc.Lock()
	tc.IPOffer = netip.Addr{}
	tc.Unlock()
	var ipOffer netip.Addr

	ether := newDHCP4DiscoverFrame(srcAddr, name, xid)
	frame, err := tc.session.Parse(ether)
	if err != nil {
		panic(err)
	}
	if err := tc.h.ProcessPacket(frame); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	tc.h.session.Notify(frame)
	select {
	case p := <-tc.notifyReply:
		frame, err = tc.session.Parse(p)
		if err != nil || frame.PayloadID != packet.PayloadDHCP4 {
			t.Fatal("invalid err or payloadID", err, frame.PayloadID)
		}
		dhcp := packet.DHCP4(frame.Payload())
		ipOffer = dhcp.YIAddr()
		options := dhcp.ParseOptions()
		if options[packet.DHCP4OptionSubnetMask] == nil || options[packet.DHCP4OptionRouter] == nil || options[packet.DHCP4OptionDomainNameServer] == nil {
			t.Fatalf("DHCPHandler.handleDiscover() missing options =%v", options)
		}
		if ip := tc.h.session.DHCPv4IPOffer(dhcp.CHAddr()); ipOffer != ip {
			t.Fatal("invalid table ip offer", ipOffer, ip)
		}

	case <-time.After(time.Millisecond * 10):
		t.Fatal("failed to receive reply")
	}

	ether = newDHCP4RequestFrame(srcAddr, dstAddr, name, hostIP4, ipOffer, xid)
	frame, err = tc.session.Parse(ether)
	if err != nil {
		panic(err)
	}
	if err = tc.h.ProcessPacket(frame); err != nil {
		t.Fatalf("Test_Requests:%s error = %v", "newDHCPHOst", err)
	}
	tc.h.session.Notify(frame)
	select {
	case p := <-tc.notifyReply:
		dhcp := packet.DHCP4(packet.UDP(packet.IP4(packet.Ether(p).Payload()).Payload()).Payload())
		if ipOffer != dhcp.YIAddr() {
			t.Fatalf("DHCPHandler.handleDiscover() invalid ip got=%v, want=%v", ipOffer, dhcp.YIAddr())
		}
		options := dhcp.ParseOptions()
		if options[packet.DHCP4OptionSubnetMask] == nil || options[packet.DHCP4OptionRouter] == nil || options[packet.DHCP4OptionDomainNameServer] == nil {
			t.Fatalf("DHCPHandler.handleDiscover() missing options =%v", options)
		}
	case <-time.After(time.Millisecond * 10):
		t.Fatal("failed to receive reply")
	}
	/**
	result := packet.Result{}
	wantHuntStage := packet.StageNormal
	if tc.h.session.IsCaptured(mac) {
		wantHuntStage = packet.StageRedirected
	}
	if !result.IsRouter || !result.Update ||
		result.SrcAddr.IP == nil || result.SrcAddr.MAC == nil ||
		result.HuntStage != wantHuntStage ||
		result.NameEntry.Name != srcAddr.MAC.String() {
		t.Fatalf("newDHCPHost() invalid update=%v isrouter=%v result=%+v ", result.Update, result.IsRouter, result)
	}
	time.Sleep(time.Millisecond * 10)
	**/

	return xid
}

func newDHCP4DeclineFrame(src packet.Addr, dst packet.Addr, declineIP netip.Addr, serverIP netip.Addr, xid []byte) packet.Ether {
	options := packet.DHCP4Options{}
	options[packet.DHCP4OptionParameterRequestList] = []byte{byte(packet.DHCP4OptionServerIdentifier), byte(packet.DHCP4OptionRequestedIPAddress)}
	options[packet.DHCP4OptionMessage] = []byte("netfilter decline")
	if serverIP.Is4() {
		options[packet.DHCP4OptionServerIdentifier] = serverIP.AsSlice()
	}
	if declineIP.Is4() {
		options[packet.DHCP4OptionRequestedIPAddress] = declineIP.AsSlice()
	}

	ether := packet.Ether(make([]byte, packet.EthMaxSize))
	ether = packet.EncodeEther(ether, syscall.ETH_P_IP, src.MAC, dst.MAC)
	ip4 := packet.EncodeIP4(ether.Payload(), 50, src.IP, dst.IP)
	udp := packet.EncodeUDP(ip4.Payload(), src.Port, dst.Port)
	dhcp := packet.EncodeDHCP4(udp.Payload(), packet.DHCP4BootRequest, packet.DHCP4Decline, src.MAC, src.IP, packet.IPv4zero, xid, false, options, options[packet.DHCP4OptionParameterRequestList])
	udp = udp.SetPayload(dhcp)
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
	var err error
	if ether, err = ether.SetPayload(ip4); err != nil {
		panic(err)
	}
	return ether
}

func newDHCP4DiscoverFrame(src packet.Addr, name string, xid []byte) packet.Ether {
	if xid == nil {
		xid = make([]byte, 4)
		rand.Read(xid)
	}
	options := packet.DHCP4Options{}
	options[packet.DHCP4OptionParameterRequestList] = []byte{byte(packet.DHCP4OptionServerIdentifier), byte(packet.DHCP4OptionRequestedIPAddress), byte(packet.DHCP4OptionDomainNameServer), byte(packet.DHCP4OptionClientIdentifier)}
	options[packet.DHCP4OptionHostName] = []byte(name)

	ether := packet.Ether(make([]byte, packet.EthMaxSize))
	ether = packet.EncodeEther(ether, syscall.ETH_P_IP, src.MAC, dhcpDst.MAC)
	ip4 := packet.EncodeIP4(ether.Payload(), 50, src.IP, dhcpDst.IP)
	udp := packet.EncodeUDP(ip4.Payload(), src.Port, dhcpDst.Port)
	dhcp := packet.EncodeDHCP4(udp.Payload(), packet.DHCP4BootRequest, packet.DHCP4Discover, src.MAC, src.IP, packet.IPv4zero, xid, false, options, options[packet.DHCP4OptionParameterRequestList])
	udp = udp.SetPayload(dhcp)
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
	var err error
	if ether, err = ether.SetPayload(ip4); err != nil {
		panic(err)
	}
	return ether
}

func newDHCP4RequestFrame(src packet.Addr, dst packet.Addr, name string, serverID netip.Addr, requestedIP netip.Addr, xid []byte) packet.Ether {
	options := packet.DHCP4Options{}
	options[packet.DHCP4OptionParameterRequestList] = []byte{byte(packet.DHCP4OptionServerIdentifier), byte(packet.DHCP4OptionRequestedIPAddress), byte(packet.DHCP4OptionDomainNameServer)}
	options[packet.DHCP4OptionRequestedIPAddress] = requestedIP.AsSlice()
	options[packet.DHCP4OptionServerIdentifier] = serverID.AsSlice()
	options[packet.DHCP4OptionHostName] = []byte(name)

	ether := packet.Ether(make([]byte, packet.EthMaxSize))
	ether = packet.EncodeEther(ether, syscall.ETH_P_IP, src.MAC, dst.MAC)
	ip4 := packet.EncodeIP4(ether.Payload(), 50, src.IP, dst.IP)
	udp := packet.EncodeUDP(ip4.Payload(), src.Port, dst.Port)
	dhcp := packet.EncodeDHCP4(udp.Payload(), packet.DHCP4BootRequest, packet.DHCP4Request, src.MAC, requestedIP, packet.IPv4zero, xid, false, options, options[packet.DHCP4OptionParameterRequestList])
	udp = udp.SetPayload(dhcp)
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
	var err error
	if ether, err = ether.SetPayload(ip4); err != nil {
		panic(err)
	}
	return ether
}

func checkLeaseTable(t *testing.T, tc *testContext, stateAllocatedCount int, stateDiscoverCount int, freeCount int) {
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
	if aCount != stateAllocatedCount {
		t.Errorf("leaseTable invalid allocated lease count want=%d got=%d", stateAllocatedCount, aCount)
	}
	if dCount != stateDiscoverCount {
		t.Errorf("leaseTable invalid discover lease count want=%d got=%d", stateDiscoverCount, dCount)
	}
	if fCount != freeCount {
		t.Errorf("leaseTable invalid free lease count want=%d got=%d", freeCount, fCount)
	}
}
