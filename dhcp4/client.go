package dhcp4

import (
	"bytes"
	"context"
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
	if debugging() {
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
	if debugging() {
		fields["mac"] = chAddr
	}
	log.WithFields(fields).Info("dhcp4: client send release to server")

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

	if tracing() {
		log.Tracef("dhcp4: send discover packet from %s ciAddr=%v xID=%v", chAddr, cIAddr, xID)
	}
	pkt := RequestPacket(Discover, chAddr, cIAddr, xID, false, options.SelectOrderOrAll(nil))
	err = h.sendDHCPPacket(h.net1.DefaultGW, pkt)
	return err
}

func dupReleasePacket(request *DHCP4) DHCP4 {
	messageid := make([]byte, 4)
	if _, err := rand.Read(messageid); err != nil {
		panic(err)
	}

	acknowledgementOptions := request.ParseOptions()

	packet := NewPacket(BootRequest)
	packet.SetCHAddr(request.CHAddr())

	packet.SetXId(messageid)
	packet.SetCIAddr(request.YIAddr())

	packet.AddOption(OptionDHCPMessageType, []byte{byte(Release)})
	packet.AddOption(OptionServerIdentifier, acknowledgementOptions[OptionServerIdentifier])

	return packet
}

func (h *Handler) sendDeclineReleasePacket(msgType MessageType, clientID []byte, serverIP net.IP, chAddr net.HardwareAddr, ciAddr net.IP, xid []byte, options Options) (err error) {
	if xid == nil {
		xid = make([]byte, 4)
		if _, err := rand.Read(xid); err != nil {
			panic(err)
		}
	}

	packet := NewPacket(BootRequest)
	packet.SetCHAddr(chAddr)
	packet.SetCIAddr(ciAddr)
	packet.SetXId(xid)
	packet.AddOption(OptionClientIdentifier, clientID)
	packet.AddOption(OptionDHCPMessageType, []byte{byte(msgType)})
	packet.AddOption(OptionServerIdentifier, serverIP.To4())
	packet.AddOption(OptionMessage, []byte("netfilter decline"))
	for k, v := range options {
		packet.AddOption(k, v)
	}
	packet.PadToMinSize()
	err = h.sendDHCPPacket(serverIP, packet)
	return err
}

func (h *Handler) sendDHCPPacket(serverAddr net.IP, packet DHCP4) (err error) {
	dstAddr := net.UDPAddr{IP: serverAddr, Port: 67}
	_, err = h.clientConn.WriteTo(packet, &dstAddr)
	if err != nil {
		log.Debug("DHCPClient failed to dial UDP ", err)
		return err
	}
	return nil
}

func (h *Handler) clientLoop() error {
	buffer := make([]byte, packet.EthMaxSize)
	for {
		n, _, err := h.clientConn.ReadFrom(buffer)

		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				time.Sleep(time.Millisecond * 2)
				continue
			}
			if h.closed { // detach called?
				return nil
			}
			return err
		}

		req := DHCP4(buffer[:n])
		if !req.IsValid() {
			fmt.Println("dhcp4: clientLoop invalid packet len", n)
			continue
		}

		options := req.ParseOptions()
		t := options[OptionDHCPMessageType]
		if len(t) != 1 {
			log.Warn("dhcp4: skiping dhcp packet with option len not 1")
			continue
		}

		clientID := getClientID(req, options)

		serverIP := net.IPv4zero
		if tmp, ok := options[OptionServerIdentifier]; ok {
			serverIP = net.IP(tmp)
		}

		fields := log.Fields{"clientID": clientID, "ip": req.YIAddr(), "server": serverIP, "xid": req.XId()}
		if serverIP.IsUnspecified() {
			log.WithFields(fields).Error("dhcp4: client offer invalid serverIP")
			continue
		}

		reqType := MessageType(t[0])

		// An offer for a fakeMAC that we initiated? Discard it.
		if bytes.Compare(req.CHAddr()[0:4], fakeMAC[0:4]) == 0 {
			continue
		}

		// Did we send this?
		if serverIP.Equal(h.net1.DHCPServer) || serverIP.Equal(h.net2.DHCPServer) {
			continue
		}

		if debugging() {
			fields["msgType"] = reqType
			fields["mac"] = req.CHAddr()
			log.WithFields(fields).Debug("dhcp4: client dhcp received")
		}

		// only interested in offer packets
		if reqType != Offer {
			continue
		}

		log.WithFields(fields).Info("dhcp4: client offer from another dhcp server")

		// Force dhcp server to release the IP
		// h.mutex.Lock()
		// _, captured := h.captureTable[string(req.CHAddr())]
		// h.mutex.Unlock()
		if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && h.engine.IsCaptured(req.CHAddr())) {
			h.forceDecline(clientID, serverIP, req.CHAddr(), req.YIAddr(), req.XId())
		}
	}
}

// ServerIsReacheable attemps to resolve "google.com" using the serverIP.
// It return nil if okay or error if server is unreachable.
func ServerIsReacheable(ctx context.Context, serverIP net.IP) (err error) {
	r := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			// return d.DialContext(ctx, "udp", "8.8.4.4:53")
			return d.DialContext(ctx, "udp", fmt.Sprintf("%s:53", serverIP))
		},
	}

	ctx2, cancel := context.WithTimeout(context.Background(), time.Second*5)
	if ctx == nil {
		ctx = ctx2
	}
	_, err = r.LookupHost(ctx, "google.com")
	cancel()

	return err
}
