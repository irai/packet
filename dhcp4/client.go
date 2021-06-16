package dhcp4

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"github.com/irai/packet"
	log "github.com/sirupsen/logrus"
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
		h.SendDiscoverPacket(tmpMAC, net.IPv4zero, xID, nil)
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
	fields := log.Fields{"clientID": clientID, "ip": clientIP, "xid": xid, "serverIP": serverIP}
	if Debug {
		fields["mac"] = chAddr
	}
	log.WithFields(fields).Info("dhcp4: client send decline to server")

	// use a copy in the goroutine
	clientID = dupBytes(clientID)
	ciAddr := net.IPv4zero // as per rfc
	chAddr = dupMAC(chAddr)
	serverIP = dupIP(serverIP)
	xid = dupBytes(xid)
	options := Options{
		OptionRequestedIPAddress: []byte(clientIP.To4()), // as per rfc
	}

	go func() {
		err := h.sendDeclineReleasePacket(Decline, clientID, serverIP, chAddr, ciAddr, xid, options)
		if err != nil {
			log.Error("dhcp4: error in send decline packet ", err)
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
	fields := log.Fields{"clientID": clientID, "ip": clientIP, "xid": xid, "serverIP": serverIP}
	if Debug {
		fields["mac"] = chAddr
	}
	log.WithFields(fields).Info("dhcp4: sent force release to server")

	// use a copy in the goroutine
	clientIP = dupIP(clientIP)
	chAddr = dupMAC(chAddr)
	clientID = dupBytes(clientID)
	serverIP = dupIP(serverIP)
	xid = dupBytes(xid)

	go func() {
		err := h.sendDeclineReleasePacket(Release, clientID, serverIP, chAddr, clientIP, xid, nil)
		if err != nil {
			log.Error("dhcp4: error in send release packet ", err)
		}

	}()
}

// SendDiscoverPacket send a DHCP discover packet to target
func (h *Handler) SendDiscoverPacket(chAddr net.HardwareAddr, cIAddr net.IP, xID []byte, options Options) (err error) {

	if Debug {
		fmt.Printf("dhcp4: send discover packet from %s ciAddr=%v xID=%v", chAddr, cIAddr, xID)
	}
	p := RequestPacket(Discover, chAddr, cIAddr, xID, false, options.SelectOrderOrAll(nil))
	srcAddr := packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostIP4.IP, Port: packet.DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: h.session.NICInfo.RouterMAC, IP: h.session.NICInfo.RouterIP4.IP, Port: packet.DHCP4ServerPort}
	err = sendDHCP4Packet(h.session.Conn, srcAddr, dstAddr, p)
	return err
}

func (h *Handler) sendDeclineReleasePacket(msgType MessageType, clientID []byte, serverIP net.IP, chAddr net.HardwareAddr, ciAddr net.IP, xid []byte, options Options) (err error) {
	if xid == nil {
		xid = make([]byte, 4)
		if _, err := rand.Read(xid); err != nil {
			panic(err)
		}
	}

	p := NewPacket(BootRequest)
	p.SetCHAddr(chAddr)
	p.SetCIAddr(ciAddr)
	p.SetXId(xid)
	p.AddOption(OptionClientIdentifier, clientID)
	p.AddOption(OptionDHCPMessageType, []byte{byte(msgType)})
	p.AddOption(OptionServerIdentifier, serverIP.To4())
	p.AddOption(OptionMessage, []byte("netfilter decline"))
	for k, v := range options {
		p.AddOption(k, v)
	}
	p.PadToMinSize()
	srcAddr := packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostIP4.IP, Port: packet.DHCP4ClientPort}
	dstAddr := packet.Addr{MAC: h.session.NICInfo.RouterMAC, IP: h.session.NICInfo.RouterIP4.IP, Port: packet.DHCP4ServerPort}
	err = sendDHCP4Packet(h.session.Conn, srcAddr, dstAddr, p)
	// err = h.sendDHCPPacket(serverIP, packet)
	return err
}

/***
func (h *Handler) sendDHCPPacket(srcAddr packet.Addr, dstAddr packet.Addr, packet DHCP4) (err error) {
	// dstAddr := packet.Addr{MAC: h.engine.NICInfo.RouterMAC, IP: h.engine.NICInfo.RouterIP4, Port: 67}
	// _, err = h.clientConn.WriteTo(packet, &dstAddr)
	sendPacket(h.clientConn, srcAddr, dstAddr, packet)
	if err != nil {
		log.Debug("DHCPClient failed to dial UDP ", err)
		return err
	}
	return nil
}
***/

func (h *Handler) processClientPacket(host *packet.Host, req DHCP4) error {
	// req := DHCP4(buffer[:n])
	if !req.IsValid() {
		fmt.Println("dhcp4: clientLoop invalid packet len")
		return packet.ErrParseFrame
	}

	options := req.ParseOptions()
	t := options[OptionDHCPMessageType]
	if len(t) != 1 {
		log.Warn("dhcp4: skiping dhcp packet with option len not 1")
		return packet.ErrParseFrame
	}

	clientID := getClientID(req, options)

	serverIP := net.IPv4zero
	if tmp, ok := options[OptionServerIdentifier]; ok {
		serverIP = net.IP(tmp)
	}

	fields := log.Fields{"clientID": clientID, "ip": req.YIAddr(), "server": serverIP, "xid": req.XId()}
	if serverIP.IsUnspecified() {
		log.WithFields(fields).Error("dhcp4: client offer invalid serverIP")
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

	if Debug {
		fields["msgType"] = reqType
		fields["mac"] = req.CHAddr()
		log.WithFields(fields).Debug("dhcp4: client dhcp received")
	}

	// only interested in offer packets
	if reqType != Offer {
		return nil
	}

	log.WithFields(fields).Info("dhcp4: client offer from another dhcp server")

	// Force dhcp server to release the IP
	if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && h.session.IsCaptured(req.CHAddr())) {
		h.forceDecline(clientID, serverIP, req.CHAddr(), req.YIAddr(), req.XId())
	}
	return nil
}
