// Credits:
// This is a modified version of the server.go in the dhcp4 library.
// Copyright (c) 2014 Skagerrak Software Limited. All rights reserved.

package dhcp4

import (
	"fmt"
	"net"

	"github.com/irai/packet"
	log "github.com/sirupsen/logrus"
)

/*****
// ListenAndServe listens on the UDP network address addr and then calls
// Serve with handler to handle requests on incoming packets.
func (h *DHCPHandler) ListenAndServe(ctx context.Context) (err error) {
	var wg sync.WaitGroup

	// Server port 67: used by dhcp server to listen for request
	// Accept incoming both broadcast and localaddr packets
	h.conn, err = net.ListenPacket("udp4", ":67")
	if err != nil {
		log.Error("dhcp4: port 67 listen error ", err)
		return err
	}
	defer h.conn.Close()

	// Client port 68: used by dhcp client to listen for dhcp packets
	// Accept incoming both broadcast and localaddr packets
	h.conn2, err = net.ListenPacket("udp4", ":68")
	if err != nil {
		log.Error("dhcp4: port 68 listen error ", err)
		return err
	}
	defer h.conn2.Close()

	// wait for context cancellation
	go func() {
		select {
		case <-ctx.Done():
			h.conn.Close()
			h.conn2.Close()
		}
	}()

	wg.Add(1)
	go func() {
		h.clientLoop(ctx)
		wg.Done()
	}()

	// Check if another DHCP exist by requesting a new offer
	go func() {
		time.Sleep(time.Second * 2)
		h.SendDiscoverPacket(net.HardwareAddr{0xff, 0xbb, 0xff, 0xbb, 0xff, 0xbb}, net.IPv4zero, []byte{0x1, 0x1, 0xff, 0xbb}, nil)
	}()

	if err = h.serverLoop(ctx, h.conn); err != nil {
		h.conn.Close()
		h.conn2.Close()
	}

	wg.Wait()

	return err
}
***/

// ProcessPacket implements PacketProcessor interface
func (h *DHCPHandler) ProcessPacket(host *packet.Host, b []byte) (*packet.Host, error) {

	ether := packet.Ether(b)
	ip4 := packet.IP4(ether.Payload())
	if !ip4.IsValid() {
		return host, packet.ErrInvalidIP4
	}
	udp := packet.UDP(ip4.Payload())
	if !udp.IsValid() || len(udp.Payload()) < 240 {
		return host, packet.ErrInvalidIP4
	}

	// Handle client packets
	if udp.DstPort() == DHCP4ClientPort {
		return h.processClientPacket(host, b)
	}

	dhcpFrame := DHCP4(udp.Payload())
	if !dhcpFrame.IsValid() {
		return host, packet.ErrParseMessage
	}

	options := dhcpFrame.ParseOptions()
	var reqType MessageType
	if t := options[OptionDHCPMessageType]; len(t) != 1 {
		log.Warn("dhcp4: skiping dhcp packet with len not 1")
		return host, packet.ErrParseMessage
	} else {
		reqType = MessageType(t[0])
		if reqType < Discover || reqType > Inform {
			log.Warn("dhcp4: skiping dhcp packet invalid type ", reqType)
			return host, packet.ErrParseMessage
		}
	}

	// retrieve the sender IP address
	// ipStr , portStr, err := net.SplitHostPort(addr.String())

	// if res := h.processDHCP(req, reqType, options, ip4.Src()); res != nil {
	var response DHCP4
	switch reqType {

	case Discover:
		response = h.handleDiscover(dhcpFrame, options)

	case Request:
		// var senderIP net.IP
		// if tmp, ok := options[OptionDefaultFingerServer]; ok {
		// senderIP = net.IP(tmp)
		// }
		response = h.handleRequest(dhcpFrame, options, ip4.Src())

	case Decline:
		response = h.handleDecline(dhcpFrame, options)

	case Release:
		response = h.handleRelease(dhcpFrame, options)

	case Offer:
		log.Error("dhcp4: got dhcp offer")

	default:
		log.Warnf("dhcp4: message type not supported %s", reqType)
	}

	if response != nil {
		// If IP not available, broadcast

		var dstAddr packet.Addr
		if ip4.Src().Equal(net.IPv4zero) || dhcpFrame.Broadcast() {
			dstAddr = packet.Addr{MAC: packet.EthBroadcast, IP: net.IPv4bcast, Port: DHCP4ClientPort}
		} else {
			dstAddr = packet.Addr{MAC: ether.Src(), IP: ip4.Src(), Port: DHCP4ClientPort}
		}

		if debugging() {
			log.Trace("dhcp4: send reply to ", dstAddr)
		}

		srcAddr := packet.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostIP4.IP, Port: DHCP4ServerPort}
		if err := h.sendPacket(srcAddr, dstAddr, response); err != nil {
			fmt.Printf("dhcp4: failed sending packet error=%s", err)
			return host, err
		}
	}
	return host, nil
}

func (h *DHCPHandler) findSubnet(mac net.HardwareAddr) (captured bool, subnet *dhcpSubnet) {
	if _, ok := h.captureTable[string(mac)]; ok {
		if tracing() {
			log.Tracef("dhcp4: use subnet2 lan=%v defaultGW=%v", h.net2.LAN, h.net2.DefaultGW)
		}
		return true, h.net2
	}
	if tracing() {
		log.Tracef("dhcp4: use subnet1 lan=%v defaultGW=%v", h.net1.LAN, h.net1.DefaultGW)
	}
	return false, h.net1
}

func getClientID(p DHCP4, options Options) []byte {
	clientID, ok := options[OptionClientIdentifier]
	if !ok {
		clientID = p.CHAddr()
	}
	return clientID
}

/***
// ServeDHCP implementes the  krowlaw.Handler interface
//
// This interface is required by dhcp4 library.
//
func (h *DHCPHandler) processDHCP(p DHCP4, msgType MessageType, options Options, senderIP net.IP) (d DHCP4) {

	switch msgType {

	case Discover:
		return h.handleDiscover(p, options)

	case Request:
		// var senderIP net.IP
		// if tmp, ok := options[OptionDefaultFingerServer]; ok {
		// senderIP = net.IP(tmp)
		// }
		return h.handleRequest(p, options, senderIP)

	case Decline:
		return h.handleDecline(p, options)

	case Release:
		return h.handleRelease(p, options)

	case Offer:
		log.Error("dhcp4: got dhcp offer")

	default:
		log.Warnf("dhcp4: message type not supported %s", msgType)
	}

	return nil
}

****/
