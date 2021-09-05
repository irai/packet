package dhcp4

import (
	"bytes"
	"errors"
	"net"
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

type leaseTable map[string]*Lease

// Lease stores a client lease
type Lease struct {
	ClientID    []byte `yaml:",omitempty"`
	State       State
	Addr        packet.Addr
	IPOffer     net.IP    `yaml:",omitempty"`
	OfferExpiry time.Time `yaml:",omitempty"`
	XID         []byte    `yaml:",omitempty"`
	Count       int       `yaml:"-"` // a counter to check for repeat packets
	Name        string
	subnet      *dhcpSubnet `yaml:"-"` // yaml does not like private fields, it will not create the fields in ther unmarshal struct
	DHCPExpiry  time.Time   `yaml:",omitempty"`
}

func (l Lease) String() string {
	line := fastlog.NewLine("", "")
	return l.FastLog(line).ToString()
	// return fmt.Sprintf("id=% x state=%s %s name=%s offer=%s captured=%v gw=%s mask=%v", l.ClientID, l.State, l.Addr, l.Name, l.IPOffer, l.subnet.Stage, l.subnet.DefaultGW, l.subnet.LAN.Mask)
}

func (l Lease) FastLog(line *fastlog.Line) *fastlog.Line {
	line.ByteArray("id", l.ClientID)
	line.String("state", l.State.String())
	line.Struct(l.Addr)
	line.String("name", l.Name)
	line.IP("offer", l.IPOffer)
	line.String("capture", l.subnet.Stage.String())
	line.IP("gw", l.subnet.DefaultGW)
	line.String("mask", l.subnet.LAN.Mask.String())
	return line
}

func (h *Handler) findByIP(ip net.IP) *Lease {
	for _, v := range h.table {
		if v.Addr.IP.Equal(ip) {
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

		if lease.subnet.LAN.IP.Mask(lease.subnet.LAN.Mask).Equal(subnet.LAN.IP.Mask(subnet.LAN.Mask)) &&
			bytes.Equal(lease.Addr.MAC, mac) {
			return lease
		}
		// fmt.Printf("dhcp4 : client changed subnet clientID=%v from=%v to=%v\n", lease.ClientID, lease.subnet.LAN, subnet.LAN)
		fastlog.NewLine(module, "client changed subnet").ByteArray("clientID", lease.ClientID).
			String("from", lease.subnet.LAN.String()).String("to", subnet.LAN.String()).Write()
	}

	lease = &Lease{}
	lease.ClientID = packet.CopyBytes(clientID)
	lease.State = StateFree
	lease.IPOffer = nil
	lease.Addr.MAC = packet.CopyMAC(mac)
	lease.Addr.IP = nil
	lease.subnet = subnet
	lease.Name = name
	h.table[string(lease.ClientID)] = lease
	if Debug {
		// fmt.Printf("dhcp4 : new lease allocated %s\n", lease)
		fastlog.NewLine(module, "new lease allocated").Struct(lease).Write()
	}
	return lease
}

func (h *Handler) delete(lease *Lease) {
	delete(h.table, string(lease.ClientID))
}

// allocIP allocates a free IP
func (h *Handler) allocIPOffer(lease *Lease, reqIP net.IP) error {
	if reqIP != nil {
		if l := h.findByIP(reqIP); l == nil || l.State == StateFree || bytes.Equal(l.ClientID, lease.ClientID) {
			if h.session.FindIP(reqIP) == nil {
				lease.IPOffer = packet.CopyIP(reqIP).To4()
				if Debug {
					// fmt.Printf("dhcp4 : offer ip=%s\n", lease.IPOffer)
					fastlog.NewLine(module, "offer").IP("ip", lease.IPOffer).Write()
				}
				return nil
			}
		}
	}

	tmpIP := dupIP(lease.subnet.LAN.IP).To4() // copy to update array
	end := uint(lease.subnet.LastIP[3])

	// bottom half
	var ip net.IP
	for lease.subnet.nextIP <= end {
		tmpIP[3] = byte(lease.subnet.nextIP)
		lease.subnet.nextIP = lease.subnet.nextIP + 1
		if l := h.findByIP(tmpIP); l == nil || l.State == StateFree {
			if h.session.FindIP(tmpIP) == nil {
				ip = tmpIP
				break
			}
		}
	}
	if ip != nil {
		lease.IPOffer = ip
		return nil
	}

	// full range in case other IPs were freed
	lease.subnet.nextIP = uint(lease.subnet.FirstIP[3])
	for lease.subnet.nextIP <= end {
		tmpIP[3] = byte(lease.subnet.nextIP)
		lease.subnet.nextIP = lease.subnet.nextIP + 1
		if l := h.findByIP(tmpIP); l == nil || l.State == StateFree {
			if h.session.FindIP(tmpIP) == nil {
				ip = tmpIP
				break
			}
		}
	}
	if ip == nil {
		return errors.New("exhausted all ips")
	}

	lease.IPOffer = ip
	if Debug {
		// fmt.Printf("dhcp4 : offer ip=%s\n", lease.IPOffer)
		fastlog.NewLine(module, "offer").IP("ip", lease.IPOffer)
	}
	return nil
}

func (h *Handler) freeLeases(now time.Time) error {
	for _, lease := range h.table {
		if lease.State != StateFree && lease.DHCPExpiry.Before(now) {
			if Debug {
				fastlog.NewLine(module, "freeing lease").Struct(lease).Write()
			}
			lease.State = StateFree
		}
	}
	return nil
}
