package dhcp4

import (
	"bytes"
	"net/netip"
	"time"

	"github.com/irai/packet"
)

// HandleRequest process client DHCPREQUEST message to servers
//
// At the ethernet and IP layer:
//    srcMAC is set to the client mac
//    srcIP is set to 0.0.0.0 or to the client IP is the IP is already configured (ie. renew or rebind)
//    dstMAC and dstIP are set to the respective broadcast address.
//
// The client is either :
// (a) requesting offered parameters from one server and implicitly
//     declining offers from all others (SELECTING)
// (b) confirming correctness of previously allocated address after,
//     e.g., system reboot (REBINDING)
// (c) extending the lease on a particular network address (RENEWING).
//
// Check server identifier from the RFC: http://www.freesoft.org/CIE/RFC/2131/24.htm
//
// RENEW
//  DHCPREQUEST generated during RENEWING state:
//  'server identifier' MUST NOT be filled in, 'requested IP address' option MUST NOT be filled in,
//  'ciaddr' MUST be filled in with client's IP address. In this situation, the client is completely configured,
//  and is trying to extend its lease. This message will be unicast,
//  so no relay agents will be involved in its transmission.
//  Because 'giaddr' is therefore not filled in, the DHCP server will trust the value in 'ciaddr',
//  and use it when replying to the client.
//
//  The client creates a DHCPREQUEST message that identifies itself and its lease. It then transmits the message directly to the server
//  that initially granted the lease, unicast. Different from the DHCPREQUEST messages used
//  in the allocation/reallocation processes, where the DHCPREQUEST is broadcast
//  The client does not need to do an ARP IP address check when it is renewing.
//
// REBIND
//  DHCPREQUEST generated during REBINDING state:
//  same as RENEWING state except that this message MUST be broadcast to the 0xffffffff IP broadcast address.
//  The DHCP server SHOULD check 'ciaddr' for correctness before replying to the DHCPREQUEST.
//
//  Having received no response from the server that initially granted the lease, the client “gives up” on
//  that server and tries to contact any server that may be able to extend its existing lease.
//  It creates a DHCPREQUEST message and puts its IP address in the CIAddr field,
//  indicating clearly that it presently owns that address. It then broadcasts the request on the local network.
//

func (h *Handler) handleRequest(host *packet.Host, p DHCP4, options Options, senderIP netip.Addr) DHCP4 {

	reqIP, serverIP := packet.IPv4zero, packet.IPv4zero

	clientID := getClientID(p, options)
	if tmp, ok := options[OptionRequestedIPAddress]; ok {
		reqIP, ok = netip.AddrFromSlice(tmp)
		if !ok || !reqIP.Is4() {
			reqIP = packet.IPv4zero
		}
	}
	if tmp, ok := options[OptionServerIdentifier]; ok {
		serverIP, ok = netip.AddrFromSlice(tmp)
		if !ok || !serverIP.Is4() {
			serverIP = packet.IPv4zero
		}
	}
	nameEntry := packet.NameEntry{Type: module, Name: string(options[OptionHostName])}

	// ---------------------------------------------------------------------
	// |              |INIT-REBOOT  |SELECTING    |RENEWING     |REBINDING |
	// ---------------------------------------------------------------------
	// |broad/unicast |broadcast    |broadcast    |unicast      |broadcast |
	// |senderIP      |MUST NOT     |MUST NOT     |IP address   |IP address|  senderIP from IP packet should be same as ciaddr
	// |server-ip     |MUST NOT     |MUST         |MUST NOT     |MUST NOT  |
	// |requested-ip  |MUST         |MUST         |MUST NOT     |MUST NOT  |
	// |ciaddr        |zero         |zero         |IP address   |IP address|
	// ---------------------------------------------------------------------
	operation := selecting
	switch {

	//  select as result of a discover msg?
	case serverIP != packet.IPv4zero:
		operation = selecting

	// renewal packet? discover packet not sent
	case reqIP == packet.IPv4zero && senderIP != packet.IPv4bcast:
		reqIP = p.CIAddr()
		operation = renewing

	// rebinding? discover packet not sent
	case reqIP == packet.IPv4zero && senderIP == packet.IPv4bcast:
		reqIP = p.CIAddr()
		operation = rebinding

	default:
		// Rebooting typically seen when the device is rejoining the network and
		// claiming the same IP. Discover packet was not sent.
		operation = rebooting
	}

	Logger.Msg("request rcvd").ByteArray("xid", p.XId()).ByteArray("clientid", clientID).IP("ip", reqIP).String("name", nameEntry.Name).MAC("chaddr", p.CHAddr()).IP("serverID", serverIP).Write()

	if Logger.IsInfo() {
		Logger.Msg("request parameters").ByteArray("xid", p.XId()).IP("ciaddr", p.CIAddr()).Bool("brd", p.Broadcast()).IP("serverIP", serverIP).Write()
	}

	// reqIP must always be filled in
	if !reqIP.IsValid() || reqIP.IsUnspecified() {
		Logger.Msg("invalid request IP").ByteArray("xid", p.XId()).String("optionIP", string(options[OptionRequestedIPAddress])).IP("ciaddr", p.CIAddr()).Write()
		return nil
	}

	captured := h.session.IsCaptured(p.CHAddr())
	subnet := h.net1
	if captured {
		subnet = h.net2
	}

	lease := h.findOrCreate(clientID, p.CHAddr(), nameEntry.Name)

	// Main switch
	switch operation {
	case selecting:
		// selecting for another server
		if serverIP != subnet.DHCPServer {
			// Keep state discover in case we get a second request
			// Free all other states - the host is trying to get an IP from the other server
			if lease.State != StateDiscover {
				lease.State = StateFree
				lease.Addr.IP = netip.Addr{}
			}

			if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && captured) {
				// The client is attempting to confirm an offer with another server
				// Send a nack to client
				Logger.Msg("request NACK - select is for another server").ByteArray("xid", p.XId()).IP("serverIP", serverIP).Uint16("secs", p.Secs()).Write()
				return nakPacket(p, subnet.DHCPServer.AsSlice(), clientID)
			}

			// almost always a new host IP
			h.session.DHCPv4Update(p.CHAddr(), reqIP, nameEntry)
			Logger.Msg("ignore select for another server").ByteArray("xid", p.XId()).IP("serverIP", serverIP).Write()
			return nil // request not for us - silently discard packet
		}

		if !bytes.Equal(lease.Addr.MAC, p.CHAddr()) || // invalid hardware
			(lease.State == StateDiscover && (!bytes.Equal(lease.XID, p.XId()) || lease.IPOffer != reqIP)) || // invalid discover request
			(lease.State == StateAllocated && lease.Addr.IP != reqIP) { // invalid request - iphone send duplicate select packets - let it pass
			// fmt.Printf("dhcp4 : request NACK - select invalid parameters %s lxid=%v leaseIP=%s\n", fields, lease.XID, lease.Addr.IP)
			Logger.Msg("request NACK - select invalid parameters").ByteArray("xid", p.XId()).ByteArray("lxid", lease.XID).IP("leaseIP", lease.Addr.IP).Write()
			return nakPacket(p, subnet.DHCPServer.AsSlice(), clientID)
		}
		Logger.Msg("request ACK - select").ByteArray("xid", p.XId()).ByteArray("clientid", clientID).IP("ip", reqIP).String("subnet", lease.subnet.ID).Write()

	case renewing:
		// If renewing then this packet was unicast to us and the client
		// previously acquired an address from us.
		if lease.State != StateAllocated ||
			lease.Addr.IP != reqIP || !bytes.Equal(lease.Addr.MAC, p.CHAddr()) ||
			lease.DHCPExpiry.Before(time.Now()) {
			Logger.Msg("request NACK - renew invalid or expired lease").ByteArray("xid", p.XId()).IP("gw", subnet.DefaultGW).Write()

			return nakPacket(p, subnet.DHCPServer.AsSlice(), clientID)
		}
		Logger.Msg("request ACK - renewing").ByteArray("xid", p.XId()).IP("ip", reqIP).Write()

	case rebooting, rebinding:
		// rebooting is a common operation and occurs when the client is rejoining the network after
		// being away or when wifi is switched off and on.
		//  - client tries to pick up previosly know IP address, with a request packet.
		//  - client has not sent discover packet

		// almost always a new host IP
		/*
			result.Update = true
			result.IsRouter = true                                   // hack to mark result as a new host
			result.SrcAddr = packet.Addr{MAC: p.CHAddr(), IP: reqIP} // ok to pass frame addr
			result.NameEntry.Name = name
			result.HuntStage = packet.StageNoChange
		*/

		// Update session with DHCP details - almost always a new host IP will be setup
		h.session.DHCPv4Update(p.CHAddr(), reqIP, nameEntry)

		if lease.State == StateFree {
			Logger.Msg("client lease does not exist").ByteArray("xid", p.XId()).IP("ip", reqIP).Write()

			if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && captured) {
				// Attempt to force other dhcp server to release the IP
				// Send a DECLINE packet to home router in case server responded with ACK
				// Do not use RELEASE as the server can still reuse the parameters and does not issue a NAK later
				go h.forceDecline(dupBytes(clientID), h.net1.DefaultGW, dupMAC(p.CHAddr()), reqIP, dupBytes(p.XId()))

				// always NACK so next attempt may trigger discover
				// also, it must return nack if moving form net2 to net1
				// in the iPhone case, this causes the iPhone to retry discover
				return nakPacket(p, h.net1.DefaultGW.AsSlice(), clientID)
			}
		}

		if lease.State != StateAllocated ||
			lease.Addr.IP != reqIP || !bytes.Equal(lease.Addr.MAC, p.CHAddr()) ||
			!subnet.LAN.Contains(lease.Addr.IP) {
			Logger.Msg("request NACK - rebooting").ByteArray("xid", p.XId()).IP("ip", reqIP).Write()

			if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && captured) {
				// Attempt to force other dhcp server to release the IP
				// Send a DECLINE packet to home router in case server responded with ACK
				// Do not use RELEASE as the server can still reuse the parameters and does not issue a NAK later
				go h.forceDecline(dupBytes(clientID), h.net1.DefaultGW, dupMAC(p.CHAddr()), reqIP, dupBytes(p.XId()))
			}

			// We have the lease but the IP or MAC don't match
			// Send NACK
			return nakPacket(p, subnet.DHCPServer.AsSlice(), clientID)
		}

		if operation == rebooting {
			Logger.Msg("request ACK - rebooting").ByteArray("xid", p.XId()).IP("ip", reqIP).Write()
		} else {
			Logger.Msg("request ACK - rebinding").ByteArray("xid", p.XId()).IP("ip", reqIP).Write()
		}

	default:
		Logger.Msg("error in request - ignore invalid operation").ByteArray("xid", p.XId()).Uint8("operation", operation).Write()
		return nil
	}

	// successful request
	lease.Name = nameEntry.Name
	if lease.State == StateDiscover {
		lease.Addr.IP = lease.IPOffer
		lease.IPOffer = netip.Addr{}
	}
	lease.State = StateAllocated
	lease.DHCPExpiry = time.Now().Add(lease.subnet.Duration)
	lease.Count = 0

	if tmp, ok := options[OptionHostName]; ok {
		lease.Name = string(tmp)
	}

	// Ack Options - same as offer options
	opts := lease.subnet.CopyOptions()
	opts[OptionIPAddressLeaseTime] = optionsLeaseTime(lease.subnet.Duration) // rfc: must include
	ret := Marshall(p, BootReply, ACK, nil, netip.Addr{}, lease.Addr.IP, nil, false, opts, options[OptionParameterRequestList])

	if Logger.IsInfo() {
		l := Logger.Msg("request ack options recv").ByteArray("xid", p.XId()).Sprintf("options", options[OptionParameterRequestList])
		l.Module(module, "request ack options sent").ByteArray("xid", p.XId()).Sprintf("options", ret.ParseOptions())
		l.Write()
	}

	h.saveConfig(h.filename)

	// Update session with DHCP details - almost always a new host IP will be setup
	h.session.DHCPv4Update(lease.Addr.MAC, lease.Addr.IP, nameEntry)

	return ret
}
