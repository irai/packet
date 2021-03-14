package dhcp4

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/irai/packet"
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
	ClientID    []byte
	State       State
	Addr        packet.Addr
	IPOffer     net.IP
	OfferExpiry time.Time
	XID         []byte `yaml:"-"`
	Count       int    `yaml:"-"` // a counter to check for repeat packets
	Name        string
	subnet      *dhcpSubnet
	DHCPExpiry  time.Time
}

// Handler is the main dhcp4 handler
type Handler struct {
	engine     *packet.Handler // engine handler
	clientConn net.PacketConn  // Listen DHCP client port
	mode       Mode            // if true, force decline and release packets to homeDHCPServer
	filename   string          // leases filename
	closed     bool            // indicates that detach function was called
	closeChan  chan bool       // channel to close underlying goroutines
	Table      leaseTable      // lease table
	net1       *dhcpSubnet     // home LAN
	net2       *dhcpSubnet     // netfilter LAN
	sync.Mutex
}

func (h *Handler) find(clientID []byte) *Lease {
	return h.Table[string(clientID)]
}

func (h *Handler) findByMAC(mac net.HardwareAddr) *Lease {
	for _, v := range h.Table {
		if bytes.Equal(v.Addr.MAC, mac) {
			return v
		}
	}
	return nil
}

func (h *Handler) findByIP(ip net.IP) *Lease {
	for _, v := range h.Table {
		if v.Addr.IP.Equal(ip) {
			return v
		}
	}
	return nil
}

func (h *Handler) findOrCreate(clientID []byte, mac net.HardwareAddr, name string) *Lease {

	var captured bool
	subnet := h.net1
	if captured = h.engine.IsCaptured(mac); captured {
		subnet = h.net2
	}

	lease := h.Table[string(clientID)]
	if lease != nil {
		if lease.Name != name {
			lease.Name = name
		}

		if lease.subnet.LAN.IP.Mask(lease.subnet.LAN.Mask).Equal(subnet.LAN.IP.Mask(subnet.LAN.Mask)) &&
			bytes.Equal(lease.Addr.MAC, mac) {
			return lease
		}
		fmt.Printf("dhcp4 : error mismatched subnet lease=%v newsubnet=%v", lease.subnet.LAN, subnet.LAN)
	}

	lease = &Lease{}
	lease.ClientID = packet.CopyBytes(clientID)
	lease.State = StateFree
	lease.IPOffer = nil
	lease.Addr.MAC = packet.CopyMAC(mac)
	lease.subnet = subnet
	lease.Name = name
	h.Table[string(lease.ClientID)] = lease
	return lease
}

func (h *Handler) delete(lease *Lease) {
	delete(h.Table, string(lease.ClientID))
}

// allocIP allocates a free IP
func (h *Handler) allocIPOffer(lease *Lease, reqIP net.IP) error {
	if reqIP != nil {
		if l := h.findByIP(reqIP); l == nil || l.State == StateFree || bytes.Equal(l.ClientID, lease.ClientID) {
			if h.engine.FindIP(reqIP) == nil {
				lease.IPOffer = packet.CopyIP(reqIP).To4()
				// fmt.Println("DEBUG ip offer 1= ", lease.IPOffer)
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
			if h.engine.FindIP(tmpIP) == nil {
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
			if h.engine.FindIP(tmpIP) == nil {
				ip = tmpIP
				break
			}
		}
	}
	if ip == nil {
		return fmt.Errorf("exhausted all ips")
	}

	// fmt.Println("DEBUG ip offer ", ip)

	lease.IPOffer = ip
	return nil
}

func (h *Handler) freeLeases(now time.Time) error {
	h.Lock()
	defer h.Unlock()

	for _, lease := range h.Table {
		if lease.DHCPExpiry.Before(now) {
			if Debug {
				fmt.Printf("dhcp4 : freeing lease %v\n", lease)
			}
			lease.State = StateFree
		}
	}
	return nil
}
