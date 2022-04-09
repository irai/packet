package dhcp4

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

// State defines type for lease state
type State int

// lease state constants
const (
	StateFree      State = 0
	StateDiscover  State = 1
	StateAllocated State = 2
)

func (e State) String() string {
	switch e {
	case StateAllocated:
		return "allocated"
	case StateDiscover:
		return "discovery"
	}
	return "free"
}

// Lease stores a client lease
type Lease struct {
	ClientID    []byte `yaml:",omitempty"`
	State       State
	Addr        packet.Addr
	IPOffer     netip.Addr `yaml:",omitempty"`
	OfferExpiry time.Time  `yaml:",omitempty"`
	XID         []byte     `yaml:",omitempty"`
	Count       int        `yaml:"-"` // a counter to check for repeat packets
	Name        string
	subnet      *dhcpSubnet `yaml:"-"` // yaml does not like private fields, it will not create the fields in ther unmarshal struct
	DHCPExpiry  time.Time   `yaml:",omitempty"`
}

func (l Lease) String() string {
	line := Logger.Msg("")
	return l.FastLog(line).ToString()
}

func (l Lease) FastLog(line *fastlog.Line) *fastlog.Line {
	line.ByteArray("id", l.ClientID)
	line.String("state", l.State.String())
	line.Struct(l.Addr)
	line.String("name", l.Name)
	line.IP("offer", l.IPOffer)
	line.String("capture", l.subnet.Stage.String())
	line.IP("gw", l.subnet.DefaultGW)
	line.String("subnet", l.subnet.LAN.String())
	line.String("subnet_id", l.subnet.ID)
	return line
}

func (h *Handler) findByIP(ip netip.Addr) *Lease {
	for _, v := range h.table {
		if v.Addr.IP == ip {
			return v
		}
	}
	return nil
}

func (h *Handler) findByMAC(mac net.HardwareAddr) *Lease {
	for _, v := range h.table {
		if bytes.Equal(v.Addr.MAC, mac) {
			return v
		}
	}
	return nil
}

func (h *Handler) findOrCreate(clientID []byte, mac net.HardwareAddr, name string) *Lease {
	var captured bool
	subnet := h.net1
	if captured = h.session.IsCaptured(mac); captured {
		subnet = h.net2
	}

	lease := h.table[string(clientID)]
	if lease != nil {
		if name != "" && lease.Name != name {
			lease.Name = name
		}
		// if lease.subnet.LAN.IP.Mask(lease.subnet.LAN.Mask).Equal(subnet.LAN.IP.Mask(subnet.LAN.Mask)) &&
		if lease.subnet.LAN == subnet.LAN &&
			bytes.Equal(lease.Addr.MAC, mac) {
			return lease
		}
		Logger.Msg("client changed subnet").ByteArray("clientID", lease.ClientID).
			String("from", lease.subnet.LAN.String()).String("to", subnet.LAN.String()).Write()
	}

	lease = &Lease{}
	lease.ClientID = packet.CopyBytes(clientID)
	lease.State = StateFree
	lease.IPOffer = netip.Addr{}
	lease.Addr.MAC = packet.CopyMAC(mac)
	lease.Addr.IP = netip.Addr{}
	lease.subnet = subnet
	lease.Name = name
	h.table[string(lease.ClientID)] = lease
	if Debug {
		// fmt.Printf("dhcp4 : new lease allocated %s\n", lease)
		Logger.Msg("new lease allocated").Struct(lease).Write()
	}
	return lease
}

func (h *Handler) delete(lease *Lease) {
	delete(h.table, string(lease.ClientID))
}

// allocIPOffer allocates a free IP to the lease entry
func (h *Handler) allocIPOffer(lease *Lease, reqIP netip.Addr) error {
	if reqIP.Is4() {
		if l := h.findByIP(reqIP); l == nil || l.State == StateFree || bytes.Equal(l.ClientID, lease.ClientID) {
			if h.session.FindIP(reqIP) == nil {
				lease.IPOffer = reqIP
				if Debug {
					Logger.Msg("offer").IP("ip", lease.IPOffer).Write()
				}
				return nil
			}
		}
	}

	// search in remaining space to deliver sequential addresses
	var ip netip.Addr
	for lease.subnet.nextIP.Less(lease.subnet.broadcast) {
		// for tmpIP.IsValid() {
		if l := h.findByIP(lease.subnet.nextIP); l == nil || l.State == StateFree {
			if h.session.FindIP(lease.subnet.nextIP) == nil {
				ip = lease.subnet.nextIP
				lease.subnet.nextIP = lease.subnet.nextIP.Next()
				break
			}
		}
		lease.subnet.nextIP = lease.subnet.nextIP.Next()
	}
	if ip.IsValid() {
		lease.IPOffer = ip
		return nil
	}

	// search across full subnet in case other IPs were freed
	lease.subnet.nextIP = lease.subnet.FirstIP
	for lease.subnet.nextIP.Less(lease.subnet.broadcast) {
		if l := h.findByIP(lease.subnet.nextIP); l == nil || l.State == StateFree {
			if h.session.FindIP(lease.subnet.nextIP) == nil {
				ip = lease.subnet.nextIP
				lease.subnet.nextIP = lease.subnet.nextIP.Next()
				break
			}
		}
		lease.subnet.nextIP = lease.subnet.nextIP.Next()
	}
	if !ip.IsValid() {
		return errors.New("exhausted all ips")
	}
	lease.IPOffer = ip
	if Debug {
		Logger.Msg("offer").IP("ip", lease.IPOffer).Write()
	}
	return nil
}

func (h *Handler) freeLeases(now time.Time) error {
	for _, lease := range h.table {
		if lease.State != StateFree && lease.DHCPExpiry.Before(now) {
			if Debug {
				Logger.Msg("freeing lease").Struct(lease).Write()
			}
			lease.State = StateFree
		}
	}
	return nil
}
