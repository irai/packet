package dhcp4

import (
	"bytes"
	"net/netip"

	"github.com/irai/packet/fastlog"
)

// handleDecline will process a DHCP decline message from a client and free up the
// entry in the dhcp table if present.
//
// Because the client is declining the use of the IP address supplied by the server,
// the client broadcasts DHCPDECLINE messages.
//
// -------------------------------------------+
// |              |DECLINE      |RELEASE      |             |          |
// -------------------------------------------+
// |broad/unicast |broadcast    |unicast      |
// |server-ip     |MUST         |MUST         |
// |requested-ip  |MUST         |MUST NOT     |
// |ciaddr        |zero         |IP address   |
// -------------------------------------------+
func (h *Handler) handleDecline(p DHCP4, options Options) (d DHCP4) {

	reqIP, _ := netip.AddrFromSlice(options[OptionRequestedIPAddress])
	serverIP, _ := netip.AddrFromSlice(options[OptionServerIdentifier])
	clientID := getClientID(p, options)

	lease := h.findOrCreate(clientID, p.CHAddr(), "")

	if lease.subnet.DHCPServer != serverIP {
		fastlog.NewLine("dhcp4", "decline for another server - ignore").ByteArray("clientid", clientID).IP("ip", reqIP).IP("serverIP", serverIP).Write()
		return nil
	}

	if lease == nil || lease.Addr.IP != reqIP || !bytes.Equal(lease.Addr.MAC, p.CHAddr()) {
		lxid := []byte{}
		if lease != nil {
			lxid = lease.XID
		}
		fastlog.NewLine("dhcp4", "decline for invalid lease - gnore").ByteArray("clientid", clientID).IP("ip", reqIP).IP("serverIP", serverIP).ByteArray("lxid", lxid).Write()
		return nil
	}

	fastlog.NewLine("dhcp4", "decline").ByteArray("clientid", clientID).IP("serverIP", serverIP).IP("ip", lease.Addr.IP).Write()
	lease.State = StateFree
	lease.Addr.IP = netip.Addr{}
	lease.IPOffer = netip.Addr{}
	return nil
}

// handleRelease will process a DHCP release message and free up the
// entry in the dhcp table if present.
//
// If the client no longer requires use of its assigned network address
// (e.g., the client is gracefully shut down), the client sends a
// DHCPRELEASE message to the server.  Note that the correct operation
// of DHCP does not depend on the transmission of DHCPRELEASE messages.
//
// The client unicasts DHCPRELEASE messages to the server.
func (h *Handler) handleRelease(p DHCP4, options Options) (d DHCP4) {
	reqIP := p.CIAddr()
	serverIP, _ := netip.AddrFromSlice(options[OptionServerIdentifier])
	clientID := getClientID(p, options)

	lease := h.findOrCreate(clientID, p.CHAddr(), "")
	if lease.subnet.DHCPServer != serverIP || lease == nil || lease.Addr.IP != reqIP {
		fastlog.NewLine("dhcp4", "release - discard invalid packet").ByteArray("clientid", clientID).IP("serverIP", serverIP).IP("reqip", reqIP).Write()
		return nil
	}
	fastlog.NewLine("dhcp4", "release").ByteArray("clientid", clientID).IP("ip", lease.Addr.IP).MAC("mac", lease.Addr.MAC).ByteArray("xid", p.XId()).Write()
	return nil
}
