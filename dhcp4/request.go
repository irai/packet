package dhcp4

import (
	"bytes"
	"net"
	"time"

	"github.com/irai/packet"
	log "github.com/sirupsen/logrus"
)

// HandleRequest process client DHCPREQUEST message to servers
//
// either :
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

func (h *Handler) handleRequest(host *packet.Host, p DHCP4, options Options, senderIP net.IP) (*packet.Host, DHCP4) {

	reqIP, serverIP := net.IPv4zero, net.IPv4zero

	clientID := getClientID(p, options)
	if tmp, ok := options[OptionRequestedIPAddress]; ok {
		reqIP = net.IP(tmp).To4()
	}
	if tmp, ok := options[OptionServerIdentifier]; ok {
		serverIP = net.IP(tmp).To4()
	}
	name := string(options[OptionHostName])
	if host != nil {
		h.engine.SetDHCP4Fields(host, packet.StageNoChange, name)
	}

	fields := log.Fields{"clientid": clientID, "ip": reqIP, "xid": p.XId(), "name": name}
	if debugging() {
		t := dupFields(fields)
		t["mac"] = p.CHAddr()
		t["ciaddr"] = p.CIAddr()
		t["serverid"] = serverIP
		t["brd"] = p.Broadcast()
		log.WithFields(t).Debug("dhcp4: request")
	}

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
	case !serverIP.Equal(net.IPv4zero):
		operation = selecting

	// renewal packet? discover packet not sent
	case reqIP.Equal(net.IPv4zero) && !senderIP.Equal(net.IPv4bcast):
		// p.Broadcast():
		reqIP = p.CIAddr()
		operation = renewing

	// rebinding? discover packet not sent
	case reqIP.Equal(net.IPv4zero) && senderIP.Equal(net.IPv4bcast):
		reqIP = p.CIAddr()
		operation = rebinding

	default:
		// Rebooting typically seen when the device is rejoining the network and
		// claiming the same IP. Discover packet was not sent.
		operation = rebooting
	}

	fields["ip"] = reqIP
	log.WithFields(fields).Info("dhcp4: request rcvd")

	// reqIP must always be filled in
	if reqIP.Equal(net.IPv4zero) {
		fields["optionIP"] = string(options[OptionRequestedIPAddress])
		fields["ciaddr"] = p.CIAddr()
		log.WithFields(fields).Error("dhcp4: request - invalid IP")
		return host, nil
	}

	// h.mutex.Lock()
	// defer h.mutex.Unlock()
	captured := h.engine.IsCaptured(p.CHAddr())
	subnet := h.net1
	if captured {
		subnet = h.net2
	}

	lease := h.findOrCreate(clientID, p.CHAddr(), name)

	// Main switch
	switch operation {
	case selecting:
		// selecting from another server
		if !serverIP.Equal(subnet.DHCPServer) {
			// Keep state discover in case we get a second request
			// Free all other states - the host is trying to get an IP from the other server
			if lease.State != StateDiscover {
				lease.State = StateFree
				lease.Addr.IP = nil
			}
			if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && captured) {
				// The client is attempting to confirm an offer with another server
				// Send a nack to client
				fields["serverid"] = serverIP
				log.WithFields(fields).Info("dhcp4: request NACK - select is for another server")
				return host, ReplyPacket(p, NAK, subnet.DHCPServer, net.IPv4zero, 0, nil)
			}

			log.WithFields(fields).Info("dhcp4: ignore select for another server")
			return host, nil // request not for us - silently discard packet
		}

		if !bytes.Equal(lease.Addr.MAC, p.CHAddr()) || // invalid hardware
			(lease.State == StateDiscover && (!bytes.Equal(lease.XID, p.XId()) || !lease.IPOffer.Equal(reqIP))) || // invalid discover request
			(lease.State == StateAllocated && !lease.Addr.IP.Equal(reqIP)) { // invalid request - iphone send duplicate select packets - let it pass
			fields["lxid"] = lease.XID
			fields["lip"] = lease.Addr.IP
			log.WithFields(fields).Info("dhcp4: request NACK - select invalid parameters")
			return host, ReplyPacket(p, NAK, subnet.DHCPServer, net.IPv4zero, 0, nil)
		}
		log.WithFields(fields).Info("dhcp4: request ACK - select")

	case renewing:
		// If renewing then this packet was unicast to us and the client
		// previously acquired an address from us.
		if lease.State != StateAllocated ||
			!lease.Addr.IP.Equal(reqIP) || !bytes.Equal(lease.Addr.MAC, p.CHAddr()) ||
			lease.DHCPExpiry.Before(time.Now()) {
			if lease != nil && debugging() {
				fields["state"] = lease.State
				fields["gw"] = subnet.DefaultGW
			}
			log.WithFields(fields).Info("dhcp4: request NACK - renew invalid or expired lease")
			// freeLease(lease)

			return host, ReplyPacket(p, NAK, subnet.DHCPServer, net.IPv4zero, 0, nil)
		}

		log.WithFields(fields).Info("dhcp4: request ACK - renewing")
		// return host, h.ackPacket(subnet, p, options, lease)

	case rebooting, rebinding:
		// rebooting is a common operation and occurs when the client is rejoining the network after
		// being away or when wifi is switched off and on.
		//  - client tries to pick up previosly know IP address, with a request packet.
		//  - client has not sent discover packet

		if lease.State == StateFree {
			log.WithFields(fields).Info("dhcp4: request NACK - rebooting for another server")

			if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && captured) {

				// Attempt to force other dhcp server to release the IP
				// Send a DECLINE packet to home router in case server responded with ACK
				// Do not use RELEASE as the server can still reuse the parameters and does not issue a NAK later
				go h.forceDecline(dupBytes(clientID), h.net1.DefaultGW, dupMAC(p.CHAddr()), dupIP(reqIP), dupBytes(p.XId()))

				// always NACK so next attempt may trigger discover
				// also, it must return nack if moving form net2 to net1
				// in the iPhone case, this causes the iPhone to retry discover
				return host, ReplyPacket(p, NAK, h.net1.DefaultGW, net.IPv4zero, 0, nil)

			}

		}

		if lease.State != StateAllocated ||
			!lease.Addr.IP.Equal(reqIP) || !bytes.Equal(lease.Addr.MAC, p.CHAddr()) ||
			!subnet.LAN.Contains(lease.Addr.IP) {
			fields["lan"] = subnet.LAN
			log.WithFields(fields).Info("dhcp4: request NACK - rebooting")

			if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && captured) {
				// Attempt to force other dhcp server to release the IP
				// Send a DECLINE packet to home router in case server responded with ACK
				// Do not use RELEASE as the server can still reuse the parameters and does not issue a NAK later
				go h.forceDecline(dupBytes(clientID), h.net1.DefaultGW, dupMAC(p.CHAddr()), dupIP(reqIP), dupBytes(p.XId()))
			}

			// We have the lease but the IP or MAC don't match
			// Send NACK
			return host, ReplyPacket(p, NAK, subnet.DHCPServer, net.IPv4zero, 0, nil)
		}

		if operation == rebooting {
			log.WithFields(fields).Info("dhcp4: request ACK - rebooting")
		} else {
			log.WithFields(fields).Info("dhcp4: request ACK - rebinding")
		}

	default:
		log.WithFields(log.Fields{"clientid": clientID, "mac": lease.Addr.MAC.String(), "ip": reqIP}).Error("dhcp4: request - ignore invalid state")
		return host, nil
	}

	// successful request
	lease.Name = name
	if lease.State == StateDiscover {
		lease.Addr.IP = lease.IPOffer
		lease.IPOffer = nil
	}
	lease.State = StateAllocated
	lease.DHCPExpiry = time.Now().Add(lease.subnet.Duration)
	lease.Count = 0

	if tmp, ok := options[OptionHostName]; ok {
		lease.Name = string(tmp)
	}
	opts := lease.subnet.options.SelectOrderOrAll(options[OptionParameterRequestList])
	ret := ReplyPacket(p, ACK, lease.subnet.DHCPServer, lease.Addr.IP, lease.subnet.Duration, opts)

	if tracing() {
		log.WithFields(log.Fields{"clientid": lease.ClientID}).Tracef("dhcp4: request ack options recv %+v", options[OptionParameterRequestList])
		log.WithFields(log.Fields{"clientid": lease.ClientID}).Tracef("dhcp4: request ack options sent %+v", opts)
	}

	h.saveConfig(h.filename)

	host, _ = h.engine.FindOrCreateHost(lease.Addr.MAC, lease.Addr.IP)
	h.engine.SetDHCP4Fields(host, lease.subnet.Stage, lease.Name)

	return host, ret
}
