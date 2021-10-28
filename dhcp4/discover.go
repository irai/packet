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

	fastlog.NewLine(module, "discover rcvd").ByteArray("xid", p.XId()).ByteArray("clientid", clientID).IP("ip", reqIP).String("name", name).Uint16("secs", p.Secs()).Write()

	lease := h.findOrCreate(clientID, p.CHAddr(), name)

	// Exhaust all IPs for a few seconds
	if true {
		// Always attack: new mode 4 April 21 ;
		// To fix forever discovery loop where client always get the IP from router but is rejected by our ARP
		// if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && lease.subnet.Stage == packet.StageRedirected) {
		// fmt.Printf("dhcp4 : discover - send 256 discover packets %s\n", fields)
		fastlog.NewLine(module, "discover - send 256 discover packets").Write()
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
			fastlog.NewLine(module, "all ips allocated, failing silently").Error(err).Write()
			h.delete(lease)
			return packet.Result{}, nil
		}
	}

	// Client can send another discovery after the entry expiry
	// Free the entry so that a new IP is generated.
	lease.State = StateDiscover
	lease.XID = packet.CopyBytes(p.XId())
	lease.OfferExpiry = now.Add(time.Second * 5)

	// Offer options
	opts := lease.subnet.CopyOptions()
	opts[OptionIPAddressLeaseTime] = optionsLeaseTime(lease.subnet.Duration) // rfc: must include

	// keep chAddr, ciAddr, xid
	ret := Marshall(p, BootReply, Offer, nil, nil, lease.IPOffer, nil, false, opts, options[OptionParameterRequestList])
	if Debug {
		fastlog.NewLine(module, "offer options").Sprintf("optrecv", options).Sprintf("optsent", ret.ParseOptions()).Write()
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
	fastlog.NewLine(module, "offer OK").ByteArray("xid", p.XId()).ByteArray("clientid", clientID).IP("ip", lease.IPOffer).Write()
	return result, ret
}
