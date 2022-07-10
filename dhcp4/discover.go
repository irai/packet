package dhcp4

import (
	"bytes"
	"fmt"
	"net/netip"
	"time"

	"github.com/irai/packet"
)

// handleDiscover respond with a DHCP offer packet
//
// At the ethernet and IP layer:
//    srcMAC is set to the client mac
//    srcIP is set to 0.0.0.0
//    dstMAC and dstIP are set to the respective broadcast address.
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
func (h *Handler) handleDiscover(p DHCP4, options Options) (d DHCP4) {

	clientID := getClientID(p, options)
	reqIP, _ := netip.AddrFromSlice(options[OptionRequestedIPAddress])
	name := string(options[OptionHostName])

	if Logger.IsInfo() {
		Logger.Msg("discover rcvd").ByteArray("xid", p.XId()).ByteArray("clientid", clientID).IP("ip", reqIP).String("name", name).Uint16("secs", p.Secs()).Write()
	}

	lease := h.findOrCreate(clientID, p.CHAddr(), name)

	// Exhaust all IPs for a few seconds
	if true {
		// Always attack: new mode 4 April 21 ;
		// if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && lease.subnet.Stage == packet.StageRedirected) {
		if Logger.IsInfo() {
			Logger.Msg("discover sending 256 discover packets").Write()
		}
		h.attackDHCPServer(options)
	}

	now := time.Now()

	switch lease.State {

	// reuse current address if valid
	case StateAllocated:
		lease.IPOffer = lease.Addr.IP
		if lease.DHCPExpiry.Before(now) { // expired
			lease.IPOffer = netip.Addr{}
		}

	// more than one discover packet
	// Android sends two discover packets in quick succession
	// If another discover within the allowed time, return the previous offer
	case StateDiscover:
		if !bytes.Equal(lease.XID, p.XId()) { // new discover packet
			lease.IPOffer = netip.Addr{}
		}
	}

	if !lease.IPOffer.IsValid() {
		if err := h.allocIPOffer(lease, reqIP); err != nil {
			Logger.Msg("discover all ips allocated, failing silently").Error(err).Write()
			h.delete(lease)
			return nil
		}
	}

	if lease.IPOffer == h.session.NICInfo.HostAddr4.IP || lease.IPOffer == h.session.NICInfo.RouterAddr4.IP {
		fmt.Println(module, "TRACE  ip allocation same as host ip or router ip", lease.IPOffer, h.session.NICInfo.HostAddr4.IP, h.session.NICInfo.RouterAddr4.IP)
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
	ret := Marshall(p, BootReply, Offer, nil, netip.Addr{}, lease.IPOffer, nil, false, opts, options[OptionParameterRequestList])
	if Logger.IsInfo() {
		Logger.Msg("discover options received").Sprintf("options", options).Write()
		Logger.Msg("discover options sent").Sprintf("options", ret.ParseOptions()).Write()
	}

	//Attemp to disrupt the lan DHCP handshake
	//  The server is likely to send offer before us, so send a kill packet
	//  assuming the other server offered the requested IP - guess
	//
	if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && lease.subnet.Stage == packet.StageRedirected) {
		if reqIP.IsValid() && !reqIP.IsUnspecified() {
			h.forceDecline(lease.ClientID, h.net1.DefaultGW, lease.Addr.MAC, reqIP, p.XId())
		}
	}

	// Set the IP4 offer to be later checked in ARP ACD
	h.session.SetDHCPv4IPOffer(lease.Addr.MAC, lease.IPOffer, packet.NameEntry{Type: module, Name: name})
	if Logger.IsInfo() {
		Logger.Msg("discover offer OK").ByteArray("xid", p.XId()).ByteArray("clientid", clientID).IP("ip", lease.IPOffer).String("subnet", lease.subnet.ID).Write()
	}
	return ret
}
