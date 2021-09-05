package dhcp4

import (
	"bytes"
	"net"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

// handleDiscover respond with a DHCP offer packet
//
// RFC2131: https://tools.ietf.org/html/rfc2131
//
// If an address is available, the new address
// SHOULD be chosen as follows:
//
// 1) The client's current address as recorded in the client's current
//    binding, ELSE
//
// 2) The client's previous address as recorded in the client's (now
//    expired or released) binding, if that address is in the server's
//    pool of available addresses and not already allocated, ELSE
//
// 3) The address requested in the 'Requested IP Address' option, if that
//    address is valid and not already allocated, ELSE
//
// 4) A new address allocated from the server's pool of available
//    addresses; the address is selected based on the subnet from which
//    the message was received (if 'giaddr' is 0) or on the address of
//    the relay agent that forwarded the message ('giaddr' when not 0).
func (h *Handler) handleDiscover(p DHCP4, options Options) (result packet.Result, d DHCP4) {

	clientID := getClientID(p, options)
	reqIP := net.IP(options[OptionRequestedIPAddress]).To4()
	name := string(options[OptionHostName])

	// fields := p.LogString(clientID, reqIP, name, nil)
	// fmt.Printf("dhcp4 : discover rcvd %s\n", fields)
	line := fastlog.NewLine(module, "discover rcvd").ByteArray("xid", p.XId()).ByteArray("clientid", clientID).IP("ip", reqIP).String("name", name)
	defer line.Write() // write a single line

	lease := h.findOrCreate(clientID, p.CHAddr(), name)
	// fmt.Println("DEBUG lease ", lease)

	// Exhaust all IPs for a few seconds
	if true {
		// Always attack: new mode 4 April 21 ;
		// To fix forever discovery loop where client always get the IP from router but is rejected by our ARP
		// if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && lease.subnet.Stage == packet.StageRedirected) {
		// fmt.Printf("dhcp4 : discover - send 256 discover packets %s\n", fields)
		line.Module(module, "discover - send 256 discover packets")
		h.attackDHCPServer(options)
	}

	now := time.Now()

	switch lease.State {

	// reuse current address if valid
	case StateAllocated:
		lease.IPOffer = lease.Addr.IP
		if lease.DHCPExpiry.Before(now) { // expired
			lease.IPOffer = nil
		}

	// more than one discover packet
	// Android sends two discover packets in quick succession
	// If another discover within the allowed time, return the previous offer
	case StateDiscover:
		if !bytes.Equal(lease.XID, p.XId()) { // new discover packet
			lease.IPOffer = nil
		}
	}

	if lease.IPOffer == nil {
		if err := h.allocIPOffer(lease, reqIP); err != nil {
			// fmt.Printf("dhcp4 : error all ips allocated, failing silently: %s", err)
			line.Module(module, "all ips allocated, failing silently").Error(err)
			h.delete(lease)
			return packet.Result{}, nil
		}
	}

	// Client can send another discovery after the entry expiry
	// Free the entry so that a new IP is generated.
	lease.State = StateDiscover
	lease.XID = packet.CopyBytes(p.XId())
	lease.OfferExpiry = now.Add(time.Second * 5)
	opts := lease.subnet.options.SelectOrderOrAll(options[OptionParameterRequestList])
	ret := ReplyPacket(p, Offer, lease.subnet.DHCPServer, lease.IPOffer, lease.subnet.Duration, opts)

	if Debug {
		// fmt.Printf("dhcp4 : offer - options %s options=%v optsent=%v\n", fields, options, ret.ParseOptions())
		line.Module(module, "offer options").Sprintf("optrecv", options).Sprintf("optsent", ret.ParseOptions())
	}

	//Attemp to disrupt the lan DHCP handshake
	//  The server is likely to send offer before us, so send a kill packet
	//  assuming the other server offered the requested IP - guess
	//
	if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && lease.subnet.Stage == packet.StageRedirected) {
		if reqIP != nil && !reqIP.IsUnspecified() {
			h.forceDecline(lease.ClientID, h.net1.DefaultGW, lease.Addr.MAC, reqIP, p.XId())
		}
	}

	// set the IP4 to be later checked in ARP ACD
	result.Update = true
	result.FrameAddr = packet.Addr{MAC: lease.Addr.MAC, IP: lease.IPOffer}

	// fmt.Printf("dhcp4 : offer OK ip=%s %s\n", lease.IPOffer, fields)
	line.Module(module, "offer OK").ByteArray("xid", p.XId()).IP("ip", lease.IPOffer)
	return result, ret
}
