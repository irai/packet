// package test provides common testing functionality across the plugins.
//
// It enables full engine testing by sending any packet type.
package test

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
	"github.com/irai/packet/dhcp4"
	"github.com/irai/packet/model"
)

var (
	ZeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	IP1     = net.IPv4(192, 168, 0, 1)
	IP2     = net.IPv4(192, 168, 0, 2)
	IP3     = net.IPv4(192, 168, 0, 3)
	IP4     = net.IPv4(192, 168, 0, 4)
	IP5     = net.IPv4(192, 168, 0, 5)

	HostMAC   = net.HardwareAddr{0x00, 0x55, 0x55, 0x55, 0x55, 0x55}
	HostIP4   = net.IPv4(192, 168, 0, 129).To4()
	RouterMAC = net.HardwareAddr{0x00, 0x66, 0x66, 0x66, 0x66, 0x66}
	RouterIP4 = net.IPv4(192, 168, 0, 11).To4()
	HomeLAN   = net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}

	MAC1 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
	MAC2 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x02}
	MAC3 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	MAC4 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x04}
	MAC5 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x05}

	ip6LLARouter = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLAHost   = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x10}
	ip6LLA1      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLA2      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	ip6LLA3      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03}
	ip6LLA4      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04}
	ip6LLA5      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05}

	HostAddrIP4   = model.Addr{MAC: HostMAC, IP: HostIP4}
	RouterAddrIP4 = model.Addr{MAC: RouterMAC, IP: RouterIP4}

	DNSGoogleIP4 = net.IPv4(8, 8, 8, 8)
)

type TestContext struct {
	inConn        net.PacketConn
	outConn       net.PacketConn
	clientInConn  net.PacketConn
	clientOutConn net.PacketConn
	Engine        *packet.Handler
	ARPHandler    *arp.Handler
	DHCP4Handler  *dhcp4.Handler
	dhcp4XID      uint16
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	responseTable [][]byte
	IPOffer       net.IP // offer received in discover
	mutex         sync.Mutex
	// savedIP       net.IP // save the returned IP for use by subsequent calls
}

func printResponseTable(tc *TestContext) {
	fmt.Println("Response table len=", len(tc.responseTable))
	for i, v := range tc.responseTable {
		fmt.Printf("  entry=%d etherType=%x\n", i, packet.Ether(v).EtherType())
	}
}

var waitingResponse int // incremented when a goroutine is awaiting a response
var waitChannel = make(chan string, 10)

func waitResponse(tc *TestContext, action Action) error {
	tc.mutex.Lock()
	waitingResponse++
	fmt.Println("test  : waiting response", action)
	tc.mutex.Unlock()
	select {
	case s := <-waitChannel:
		fmt.Println("test  : got response", s)
	case <-time.After(time.Second * 10):
		return packet.ErrTimeout
	}
	return nil
}

func readResponse(ctx context.Context, tc *TestContext) error {
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
		if !ether.IsValid() {
			s := fmt.Sprintf("error ether client packet %s", ether)
			panic(s)
		}

		// used for debuging - disable to avoid verbose logging
		if false {
			fmt.Printf("test  : got test response=%s\n", ether)
		}

		notify := ""
		if ether.EtherType() == syscall.ETH_P_IP { // IP4?
			ip4 := packet.IP4(ether.Payload())
			if !ip4.IsValid() {
				fmt.Println("invalid ip4 packet ", len(ether.Payload()), ether.Payload())
				continue
			}
			if ip4.Protocol() == syscall.IPPROTO_UDP { // UDP?
				if udp := packet.UDP(ip4.Payload()); udp.DstPort() == packet.DHCP4ClientPort { // DHCP client port?
					dhcp4Frame := dhcp4.DHCP4(udp.Payload())
					options := dhcp4Frame.ParseOptions()
					var reqType dhcp4.MessageType
					if t := options[dhcp4.OptionDHCPMessageType]; len(t) != 1 {
						continue
					} else {
						reqType = dhcp4.MessageType(t[0])
					}
					if reqType == dhcp4.Offer {
						ip := dhcp4Frame.YIAddr().To4()
						if ip == nil {
							panic("ip is nil")
						}
						tc.IPOffer = ip
						// fmt.Printf("raw: received dhcp offer=%s\n", ip)
					}

					// notify if required
					switch reqType {
					case dhcp4.Offer:
						notify = "dhcp4Discover"
					case dhcp4.ACK, dhcp4.NAK:
						notify = "dhcp4Request"
					}
				}
			}
		}

		tmp := make([]byte, len(buf))
		copy(tmp, buf)

		tc.mutex.Lock()
		tc.responseTable = append(tc.responseTable, tmp)
		if notify != "" {
			// fmt.Println("test  : notification response", notify)
			waitChannel <- notify
			waitingResponse = waitingResponse - 1
		}
		tc.mutex.Unlock()
	}
}

func NewTestContext() *TestContext {

	var err error

	tc := TestContext{}
	tc.ctx, tc.cancel = context.WithCancel(context.Background())

	tc.inConn, tc.outConn = packet.TestNewBufferedConn()
	go readResponse(tc.ctx, &tc) // MUST read the out conn to avoid blocking the sender

	tc.clientInConn, tc.clientOutConn = packet.TestNewBufferedConn()
	go packet.TestReadAndDiscardLoop(tc.ctx, tc.clientOutConn) // must read to avoid blocking

	nicInfo := model.NICInfo{
		HostMAC:   HostMAC,
		HostIP4:   net.IPNet{IP: HostIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterIP4: net.IPNet{IP: RouterIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterMAC: RouterMAC,
		HomeLAN4:  HomeLAN,
	}

	// override handler with conn and nicInfo
	config := packet.Config{Conn: tc.inConn, NICInfo: &nicInfo, ProbeInterval: time.Millisecond * 500, OfflineDeadline: time.Millisecond * 500, PurgeDeadline: time.Second * 2}
	tc.Engine, err = config.NewEngine("eth0")
	if err != nil {
		panic(err)
	}
	if packet.Debug {
		fmt.Println("nicinfo: ", tc.Engine.Session().NICInfo)
	}

	tc.ARPHandler, err = arp.New(tc.Engine.Session())
	if err != nil {
		panic(err)
	}

	// Default dhcp engine
	netfilterIP, err := packet.SegmentLAN("eth0",
		net.IPNet{IP: HostIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		net.IPNet{IP: RouterIP4, Mask: net.IPv4Mask(255, 255, 255, 0)})
	if err != nil {
		panic(err)
	}
	tc.DHCP4Handler, err = dhcp4.Config{ClientConn: tc.clientInConn}.Attach(tc.Engine.Session(), netfilterIP, DNSGoogleIP4, "")
	if err != nil {
		panic("cannot create handler" + err.Error())
	}
	tc.DHCP4Handler.SetMode(dhcp4.ModeSecondaryServerNice)

	go func() {
		if err := tc.Engine.ListenAndServe(tc.ctx); err != nil {
			panic(err)
		}
	}()

	time.Sleep(time.Millisecond * 10) // time for all goroutine to start
	return &tc
}

// GetResponse returns a goroutine safe response
func (tc *TestContext) GetResponse(index int) []byte {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	return tc.responseTable[index]
}

func (tc *TestContext) Close() {
	time.Sleep(time.Millisecond * 20) // wait for all packets to finish
	if packet.Debug {
		fmt.Println("teminating context")
	}
	tc.cancel()
	tc.wg.Wait()
}

type TestEvent struct {
	name             string
	action           Action // capture, block, accept, release, event
	packetEvent      packet.Notification
	waitTimeAfter    time.Duration
	wantCapture      bool
	wantStage        model.HuntStage
	wantOnline       bool
	hostTableInc     int // expected increment
	macTableInc      int // expected increment
	responseTableInc int // expected increment
	responsePos      int // position of response in responseTable -1 is the last entry
	srcAddr          model.Addr
	dstAddr          model.Addr
	dhcpHostName     string // dhcp host name
	ether            packet.Ether
	wantHost         *model.Host
}

func newDHCP4DiscoverFrame(src model.Addr, xid []byte, hostName string) packet.Ether {
	options := []dhcp4.Option{}
	oDNS := dhcp4.Option{Code: dhcp4.OptionDomainNameServer, Value: []byte{}}
	options = append(options, oDNS)
	if hostName != "" {
		oName := dhcp4.Option{Code: dhcp4.OptionHostName, Value: []byte(hostName)}
		options = append(options, oName)
	}

	var err error
	ether := packet.Ether(make([]byte, packet.EthMaxSize))
	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, src.MAC, arp.EthernetBroadcast)
	ip4 := packet.IP4MarshalBinary(ether.Payload(), 50, src.IP, net.IPv4zero)
	udp := packet.UDPMarshalBinary(ip4.Payload(), packet.DHCP4ClientPort, packet.DHCP4ServerPort)
	dhcp4Frame := dhcp4.RequestPacket(dhcp4.Discover, src.MAC, src.IP, xid, false, options)
	udp, err = udp.AppendPayload(dhcp4Frame)
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
	if ether, err = ether.SetPayload(ip4); err != nil {
		panic(err.Error())
	}
	return ether
}

func newDHCP4RequestFrame(src model.Addr, serverID net.IP, requestedIP net.IP, xid []byte, hostName string) packet.Ether {
	options := []dhcp4.Option{}
	oDNS := dhcp4.Option{Code: dhcp4.OptionDomainNameServer, Value: []byte{}}
	oReqIP := dhcp4.Option{Code: dhcp4.OptionRequestedIPAddress, Value: requestedIP}
	oServerID := dhcp4.Option{Code: dhcp4.OptionServerIdentifier, Value: serverID}
	options = append(options, oDNS)
	options = append(options, oReqIP)
	options = append(options, oServerID)
	if hostName != "" {
		oName := dhcp4.Option{Code: dhcp4.OptionHostName, Value: []byte(hostName)}
		options = append(options, oName)
	}

	var err error
	ether := packet.Ether(make([]byte, packet.EthMaxSize))
	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, src.MAC, arp.EthernetBroadcast)
	ip4 := packet.IP4MarshalBinary(ether.Payload(), 50, src.IP, net.IPv4zero)
	udp := packet.UDPMarshalBinary(ip4.Payload(), packet.DHCP4ClientPort, packet.DHCP4ServerPort)
	dhcp4Frame := dhcp4.RequestPacket(dhcp4.Request, src.MAC, requestedIP, xid, false, options)
	udp, err = udp.AppendPayload(dhcp4Frame)
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
	if ether, err = ether.SetPayload(ip4); err != nil {
		panic(err.Error())
	}
	return ether
}

func newARPFrame(src model.Addr, dst model.Addr, operation uint16) packet.Ether {
	var err error
	ether := packet.Ether(make([]byte, packet.EthMaxSize))
	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_ARP, src.MAC, dst.MAC)
	arpFrame, err := arp.MarshalBinary(ether.Payload(), operation, src.MAC, src.IP, dst.MAC, dst.IP)
	if ether, err = ether.SetPayload(arpFrame); err != nil {
		panic(err.Error())
	}
	return ether
}

func newArpAnnoucementEvent(addr model.Addr, hostInc int, macInc int) []TestEvent {
	return []TestEvent{
		{name: "arp-announcement-" + addr.MAC.String(), action: "arpAnnouncement", hostTableInc: hostInc, macTableInc: macInc, responsePos: -1, responseTableInc: 0,
			srcAddr:       addr,
			wantHost:      &model.Host{IP: addr.IP, Online: true},
			waitTimeAfter: time.Millisecond * 10,
		},
	}
}

// Action identifies a test event action
type Action string

// Possible event action
const (
	ActionDHCP4Discover   Action = "dhcp4Discover"
	ActionDHCP4Request    Action = "dhcp4Request"
	ActionDHCP4Decline    Action = "dhcp4Decline"
	ActionARPProbe        Action = "arpProbe"
	ActionARPAnnouncement Action = "arpAnnouncement"
)

func NewHost(t *testing.T, tc *TestContext, addr model.Addr, hostName string, hostInc int, macInc int) error {
	events := NewHostEvents(addr, hostName, hostInc, macInc)
	for _, v := range events {
		runAction(t, tc, v)
	}
	return nil
}

func NewHostEvents(addr model.Addr, hostName string, hostInc int, macInc int) []TestEvent {
	return []TestEvent{
		{name: "discover-" + addr.MAC.String(), action: "dhcp4Discover", hostTableInc: 0, macTableInc: macInc, responsePos: -1, responseTableInc: -1,
			srcAddr:       model.Addr{MAC: addr.MAC, IP: net.IPv4zero},
			dhcpHostName:  hostName,
			wantHost:      nil, // don't validate host
			waitTimeAfter: time.Millisecond * 10,
		},
		{name: "request-" + addr.MAC.String(), action: "dhcp4Request", hostTableInc: hostInc, macTableInc: 0, responsePos: -1, responseTableInc: -1,
			srcAddr:       model.Addr{MAC: addr.MAC, IP: net.IPv4zero},
			dhcpHostName:  hostName,
			wantHost:      &model.Host{IP: nil, Online: true},
			waitTimeAfter: time.Millisecond * 50,
		},
		{name: "arp-probe-" + addr.MAC.String(), action: "arpProbe", hostTableInc: 0, macTableInc: 0, responsePos: -1, responseTableInc: 0,
			srcAddr:       model.Addr{MAC: addr.MAC, IP: net.IPv4zero},
			wantHost:      &model.Host{IP: nil, Online: true},
			waitTimeAfter: time.Millisecond * 10,
		},
		{name: "arp-announcement-" + addr.MAC.String(), action: "arpAnnouncement", hostTableInc: 0, macTableInc: 0, responsePos: -1, responseTableInc: 0,
			srcAddr:       model.Addr{MAC: addr.MAC, IP: nil}, // set IP to zero to use savedIP
			wantHost:      &model.Host{IP: nil, Online: true},
			waitTimeAfter: time.Millisecond * 10,
		},
	}
}

var buf = make([]byte, packet.EthMaxSize)

func runAction(t *testing.T, tc *TestContext, tt TestEvent) {
	sendPacket := true

	switch tt.action {
	case "capture":
		t.Log("send capture ")
		tc.Engine.Capture(tt.srcAddr.MAC)
		sendPacket = false
	case "release":
		t.Log("send release ")
		tc.Engine.Capture(tt.srcAddr.MAC)
		sendPacket = false
	case "dhcp4Request":
		t.Log("send dhcp4Request ")
		if tt.srcAddr.IP == nil || tt.srcAddr.IP.Equal(net.IPv4zero) {
			tt.ether = newDHCP4RequestFrame(tt.srcAddr, HostIP4, tc.IPOffer, []byte(fmt.Sprintf("%d", tc.dhcp4XID)), tt.dhcpHostName)
		} else {
			tt.ether = newDHCP4RequestFrame(tt.srcAddr, HostIP4, tt.srcAddr.IP, []byte(fmt.Sprintf("%d", tc.dhcp4XID)), tt.dhcpHostName)
		}

	case "dhcp4Discover":
		t.Log("send dhcp4Discover ")
		tc.dhcp4XID++
		tt.ether = newDHCP4DiscoverFrame(tt.srcAddr, []byte(fmt.Sprintf("%d", tc.dhcp4XID)), tt.dhcpHostName)

	case "arpProbe":
		t.Log("send arpProbe ")
		if tc.IPOffer == nil {
			panic("invalid IPOffer")
		}
		tt.ether = newARPFrame(tt.srcAddr, model.Addr{MAC: arp.EthernetBroadcast, IP: tc.IPOffer}, arp.OperationRequest)

	case "arpAnnouncement":
		t.Log("send arpAnnouncement ")
		if tt.srcAddr.IP == nil {
			if tc.IPOffer == nil {
				panic("invalid IPOffer")
			}
			tt.srcAddr.IP = tc.IPOffer
		}
		tt.ether = newARPFrame(model.Addr{MAC: tt.srcAddr.MAC, IP: tt.srcAddr.IP.To4()}, model.Addr{MAC: arp.EthernetBroadcast, IP: tt.srcAddr.IP.To4()}, arp.OperationRequest)

	default:
		fmt.Println("invalid action")
		return
	}

	tc.mutex.Lock()
	savedResponseTableCount := len(tc.responseTable)
	tc.mutex.Unlock()
	savedHostTableCount := len(tc.Engine.Session().HostTable.Table)
	savedMACTableCount := len(tc.Engine.Session().MACTable.Table)

	if sendPacket {
		if _, err := tc.outConn.WriteTo(tt.ether, &model.Addr{MAC: tt.ether.Dst()}); err != nil {
			panic(err.Error())
		}
	}

	switch tt.action {
	case "dhcp4Request", "dhcp4Discover":
		// wait for response if DHCP packet
		// CAUTION: must wait always for DHCP response because the response will be written to the channel
		if err := waitResponse(tc, tt.action); err != nil {
			t.Fatalf("%s: error waiting for response for=%s %s", tt.name, tt.action, err)
		}
		time.Sleep(time.Millisecond * 5) // give time to update online/offline entries
	default:
		time.Sleep(tt.waitTimeAfter)
	}

	if n := len(tc.Engine.Session().HostTable.Table) - savedHostTableCount; tt.hostTableInc > 0 && n != tt.hostTableInc {
		t.Errorf("%s: invalid host table len want=%v got=%v", tt.name, tt.hostTableInc, n)
		tc.Engine.PrintTable()
	}
	if n := len(tc.Engine.Session().MACTable.Table) - savedMACTableCount; n != tt.macTableInc {
		t.Errorf("%s: invalid mac table len want=%v got=%v", tt.name, tt.macTableInc, n)
		tc.Engine.PrintTable()
	}
	tc.mutex.Lock()
	if n := len(tc.responseTable) - savedResponseTableCount; tt.responseTableInc > 0 && n != tt.responseTableInc {
		t.Errorf("%s: invalid response count len want=%v got=%v", tt.name, tt.responseTableInc, n)
		printResponseTable(tc)
	}
	tc.mutex.Unlock()

	if false && savedResponseTableCount > 0 {
		printResponseTable(tc)
	}

	if tt.wantHost != nil {
		ip := tt.wantHost.IP
		if ip == nil {
			ip = tc.IPOffer
		}
		host := tc.Engine.Session().FindIP(ip)
		if host == nil {
			t.Errorf("%s: host not found in table ip=%s ", tt.name, ip)
			tc.Engine.PrintTable()
			return
		}
		if host.Online != tt.wantHost.Online {
			t.Errorf("%s: host incorrect online status want=%v got=%v ", tt.name, tt.wantHost.Online, host.Online)
		}
	}
}

func checkOnlineCount(t *testing.T, tc *TestContext, online int, offline int) {
	countOnline, countOffline := 0, 0
	n := 0
	for _, v := range tc.Engine.Session().HostTable.Table {
		if v.Online {
			countOnline++
		} else {
			countOffline++
		}
	}

	t.Run("online check", func(t *testing.T) {
		if countOnline != online {
			n++
			t.Errorf("%s: invalid n online entries want=%v got=%v", "online", online, countOnline)
		}
		if countOffline != offline {
			n++
			t.Errorf("%s: invalid n offline entries want=%v got=%v", "offline", offline, countOffline)
		}
	})
	if n > 0 {
		tc.Engine.PrintTable()
	}
}

func checkCaptureCount(t *testing.T, tc *TestContext, nHosts int, nMACs int) {
	countHosts, countMacs := 0, 0
	n := 0
	for _, v := range tc.Engine.Session().MACTable.Table {
		if v.Captured {
			countMacs++
		}
		for _, host := range v.HostList {
			if host.MACEntry.Captured {
				countHosts++
			}
		}
	}

	t.Run("capture check", func(t *testing.T) {
		if countHosts != nHosts {
			n++
			t.Errorf("capturedhosts: invalid n hosts in capture mode want=%v got=%v", nHosts, countHosts)
		}
		if countMacs != nMACs {
			n++
			t.Errorf("capturedmacs: invalid n macs in capture mode want=%v got=%v", nMACs, countMacs)
		}
	})
	if n > 0 {
		tc.Engine.PrintTable()
	}
}
