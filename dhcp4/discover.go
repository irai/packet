package dhcp4

import (
	"bytes"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// HandleDiscover respond with a DHCP offer packet
//
// +------------------+------------------------+
// | Current State    |    Action              |
// |------------------|------------------------|
// | Free             |  Offer new IP          |
// | Discovery        |  Offer new IP          |
// | Allocated        |  Offer same IP         |
// |------------------|------------------------|
//
func (h *Handler) handleDiscover(p DHCP4, options Options) (d DHCP4) {

	clientID := getClientID(p, options)
	reqIP := net.IP(options[OptionRequestedIPAddress]).To4()
	name := string(options[OptionHostName])

	fields := log.Fields{"clientid": clientID, "name": name, "xid": p.XId()}
	log.WithFields(fields).Info("dhcp4: discover rcvd")

	if debugging() {
		t := dupFields(fields)
		t["brd"] = p.Broadcast()
		t["ip"] = reqIP
		t["mac"] = p.CHAddr()
		log.WithFields(t).Debug("dhcp4: discover parameters")
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	captured, subnet := h.findSubnet(p.CHAddr())
	lease := subnet.findCliendID(clientID)

	// Exhaust all IPs for a few seconds
	if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && captured) {
		log.WithFields(fields).Info("dhcp4: discover - send 256 discover packets")
		h.attackDHCPServer(options)
	}

	now := time.Now()
	// Android sends two discover packets in quick succession
	// If another discover within the allowed time, return the previous offer
	if lease != nil {
		switch lease.State {
		case StateDiscovery: // more than one discover packet
			if bytes.Equal(lease.XID, p.XId()) && lease.Count < 3 {
				lease.Count++
				fields["count"] = lease.Count
				log.WithFields(fields).Info("dhcp4: offer - offer same ip")

				opts := subnet.options.SelectOrderOrAll(options[OptionParameterRequestList])
				ret := ReplyPacket(p, Offer, subnet.DHCPServer, lease.IP, subnet.Duration, opts)
				if debugging() {
					fields["options"] = opts
					log.WithFields(fields).Debug("dhcp4: offer options")
				}
				return ret
			}

		case StateAllocated:
			// Attempt to reuse IP if discover happens before lease expire
			if lease.DHCPExpiry.After(now) && reqIP == nil && subnet.LAN.Contains(lease.IP) {
				t := fields
				t["lan"] = subnet.LAN
				log.WithFields(t).Debug("dhcp4: offer - lease still valid offer same ip")
				reqIP = lease.IP
			}
		}

		// Client can send another discovery after the entry expiry
		// Free the entry so that a new IP is generated.
		freeLease(lease)
	}

	lease = subnet.newLease(StateDiscovery, clientID, p.CHAddr(), reqIP, p.XId())
	if lease == nil {
		log.WithFields(fields).Error("dhcp4: discover - all IPs allocated, failing silently")
		return nil
	}

	opts := subnet.options.SelectOrderOrAll(options[OptionParameterRequestList])
	ret := ReplyPacket(p, Offer, subnet.DHCPServer, lease.IP, subnet.Duration, opts)

	if debugging() {
		t := dupFields(fields)
		t["optsrecv"] = options
		t["optssent"] = ret.ParseOptions()
		log.WithFields(t).Debug("dhcp4: offer - options")
	}

	//Attemp to disrupt the lan DHCP handshake
	//  The server is likely to send offer before us, so send a kill packet
	//  assuming the other server offered the requested IP - guess
	//
	if h.mode == ModeSecondaryServer || (h.mode == ModeSecondaryServerNice && captured) {
		if reqIP != nil && !reqIP.IsUnspecified() {
			h.forceDecline(lease.ClientID, h.net1.DefaultGW, lease.MAC, reqIP, p.XId())
		}
	}

	fields["ip"] = lease.IP
	log.WithFields(fields).Info("dhcp4: offer OK")
	return ret
}
