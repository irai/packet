package dhcp4

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

var (
	nextAttack = time.Now()
	fakeMAC    = net.HardwareAddr{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0x0}
)

func (h *Handler) attackDHCPServer(options Options) {
	if nextAttack.After(time.Now()) {
		return
	}

	xID := []byte{0xff, 0xee, 0xdd, 0}
	tmpMAC := net.HardwareAddr{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0x0}
	copy(fakeMAC[:], tmpMAC) // keep for comparison

	for i := 0; i < 256; i++ {
		xID[3] = byte(i)
		tmpMAC[5] = byte(i)
		h.SendDiscoverPacket(tmpMAC, net.IPv4zero, xID, "")
	}

	// Wait a few seconds before storming again
	nextAttack = time.Now().Add(time.Second * 20)
}

// forceDecline send a fake decline packet to force release of the IP so the
// client has to discover again when trying to renew.
//
// In most cases the home dhcp will mark the entry but keep the entry in the table
// This is an error state and the DHCP server should tell the administrator
func (h *Handler) forceDecline(clientID []byte, serverIP net.IP, chAddr net.HardwareAddr, clientIP net.IP, xid []byte) {
	fastlog.NewLine("dhcp4", "client send decline to server").ByteArray("xid", xid).ByteArray("clientid", clientID).IP("ip", clientIP).Write()

	// use a copy in the goroutine
	clientID = dupBytes(clientID)
	chAddr = dupMAC(chAddr)
	ciAddr := net.IPv4zero // as per rfc
	serverIP = dupIP(serverIP)
	xid = dupBytes(xid)
	opts := Options{}
	opts[OptionClientIdentifier] = clientID
	opts[OptionServerIdentifier] = serverIP.To4()
	opts[OptionMessage] = []byte("netfilter decline")
	opts[OptionRequestedIPAddress] = []byte(clientIP.To4())
	go func() {
		err := h.sendDeclineReleasePacket(Decline, clientID, serverIP, chAddr, ciAddr, xid, opts)
		if err != nil {
			fmt.Println("dhcp4: error in send decline packet ", err)
		}

	}()
}

// forceRelease send a fake release packet to force release of the IP so the
// client has to discover again when trying to renew.
//
// In most cases the home dhcp will drop the entry and will have an empty dhcp table
//
// Jan 21 - NOT working; the test router does not drop the entry. WHY?
func (h *Handler) forceRelease(clientID []byte, serverIP net.IP, chAddr net.HardwareAddr, clientIP net.IP, xid []byte) {
	fastlog.NewLine("dhcp4", "client send release to server").ByteArray("xid", xid).ByteArray("clientid", clientID).IP("ip", clientIP).Write()

	// use a copy in the goroutine
	clientIP = dupIP(clientIP)
	chAddr = dupMAC(chAddr)
	clientID = dupBytes(clientID)
	serverIP = dupIP(serverIP)
	xid = dupBytes(xid)
	opts := Options{}
	opts[OptionClientIdentifier] = clientID
	opts[OptionServerIdentifier] = serverIP.To4()
	opts[OptionMessage] = []byte("netfilter release")

	go func() {
		err := h.sendDeclineReleasePacket(Release, clientID, serverIP, chAddr, clientIP, xid, nil)
		if err != nil {
			fmt.Println("dhcp4: error in send release packet ", err)
		}

	}()
}

func mustXID(xid []byte) []byte {
	if xid == nil {
		xid = make([]byte, 4)
		if _, err := rand.Read(xid); err != nil {
			panic(err)
		}
	}
	return xid
}

func (h *Handler) sendDeclineReleasePacket(msgType MessageType, clientID []byte, serverIP net.IP, chAddr net.HardwareAddr, ciAddr net.IP, xid []byte, options Options) (err error) {
	b := packet.EtherBufferPool.Get().(*[packet.EthMaxSize]byte)
	defer packet.EtherBufferPool.Put(b)
	xid = mustXID(xid)
	p := Marshall(b[0:], BootRequest, msgType, chAddr, ciAddr, net.IPv4zero, xid, false, options, nil)

	srcAddr := packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostIP4.IP, Port: DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: h.session.NICInfo.RouterMAC, IP: h.session.NICInfo.RouterIP4.IP, Port: DHCP4ServerPort}
	err = sendDHCP4Packet(h.session.Conn, srcAddr, dstAddr, p)
	return err
}

// SendDiscoverPacket send a DHCP discover packet to target
func (h *Handler) SendDiscoverPacket(chAddr net.HardwareAddr, ciAddr net.IP, xid []byte, name string) (err error) {
	if Debug {
		fastlog.NewLine(module, "send discover packet").ByteArray("xid", xid).MAC("from", chAddr).IP("ciaddr", ciAddr).Write()
	}
	// Commond options seen on many dhcp clients
	options := Options{}
	if name != "" {
		options[OptionHostName] = []byte(name)
	}
	options[OptionParameterRequestList] = []byte{
		byte(OptionDHCPMessageType), byte(OptionSubnetMask),
		byte(OptionClasslessRouteFormat), byte(OptionRouter),
		byte(OptionDomainNameServer), byte(OptionDomainName),
	}

	srcAddr := packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostIP4.IP, Port: DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: h.session.NICInfo.RouterMAC, IP: h.session.NICInfo.RouterIP4.IP, Port: DHCP4ServerPort}

	b := packet.EtherBufferPool.Get().(*[packet.EthMaxSize]byte)
	defer packet.EtherBufferPool.Put(b)
	ether := packet.Ether(b[0:])
	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, srcAddr.MAC, dstAddr.MAC)
	ip4 := packet.IP4MarshalBinary(ether.Payload(), 50, srcAddr.IP, dstAddr.IP)
	udp := packet.UDPMarshalBinary(ip4.Payload(), srcAddr.Port, dstAddr.Port)
	dhcp := Marshall(udp.Payload(), BootRequest, Discover, chAddr, ciAddr, net.IPv4zero, xid, false, options, nil)
	udp = udp.SetPayload(dhcp)
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
	if ether, err = ether.SetPayload(ip4); err != nil {
		return err
	}
	if _, err := h.session.Conn.WriteTo(ether, &dstAddr); err != nil {
		fmt.Println("icmp failed to write ", err)
		return err
	}
	return nil
}

func (h *Handler) processClientPacket(host *packet.Host, req DHCP4) error {
	if err := req.IsValid(); err != nil {
		return err
	}

	options := req.ParseOptions()
	t := options[OptionDHCPMessageType]
	if len(t) != 1 {
		fmt.Println("dhcp4: skiping dhcp packet with option len not 1")
		return packet.ErrParseFrame
	}

	clientID := getClientID(req, options)
	serverIP := net.IPv4zero
	if tmp, ok := options[OptionServerIdentifier]; ok {
		serverIP = net.IP(tmp)
	}

	if serverIP.IsUnspecified() {
		fmt.Printf("dhcp4: error client offer invalid serverIP=%v clientID=%v\n", serverIP, clientID)
		return packet.ErrParseFrame
	}

	reqType := MessageType(t[0])

	// An offer for a fakeMAC that we initiated? Discard it.
	if bytes.Equal(req.CHAddr()[0:4], fakeMAC[0:4]) {
		return nil
	}

	// Did we send this?
	if serverIP.Equal(h.net1.DHCPServer) || serverIP.Equal(h.net2.DHCPServer) {
		return nil
	}

	// only interested in offer packets
	if reqType != Offer {
		return nil
	}

	fastlog.NewLine("dhcp4", "client offer from another dhcp server").ByteArray("xid", req.XId()).ByteArray("clientid", clientID).IP("ip", req.YIAddr()).Write()

	// Force dhcp server to release the IP
	if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && h.session.IsCaptured(req.CHAddr())) {
		h.forceDecline(clientID, serverIP, req.CHAddr(), req.YIAddr(), req.XId())
	}
	return nil
}
