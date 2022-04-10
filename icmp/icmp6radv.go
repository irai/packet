package icmp

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/irai/packet"
)

var (
	RDNSSCLoudflare = &packet.RecursiveDNSServer{
		Lifetime: time.Minute * 10,
		Servers:  []net.IP{packet.DNSv6Cloudflare1.AsSlice(), packet.DNSv6Cloudflare2.AsSlice()},
	}
)

// Router holds a router identification and is useful to implement
// Router Advertisement Servers.
//
// As of April 22,
// THIS IS INCOMPLETE and not working yet
type Router struct {
	Addr            packet.Addr
	enableRADVS     bool // if true, we respond for this server
	ManagedFlag     bool // if true, hosts should get IP from DHCP, if false, use SLAAC IP
	OtherCondigFlag bool // if true, hosts should get other info from DHCP
	Preference      byte
	MTU             uint32
	ReacheableTime  int // Must be no greater than 3,600,000 milliseconds (1hour)
	RetransTimer    int //
	CurHopLimit     uint8
	DefaultLifetime time.Duration // A value of zero means the router is not to be used as a default router
	Prefixes        []packet.PrefixInformation
	RDNSS           *packet.RecursiveDNSServer // Pointer to facilitate comparison
	Options         packet.NewOptions
}

func (r *Router) String() string {
	return fmt.Sprintf("%s preference=%v prefix=%v\n", r.Addr, r.Preference, r.Prefixes)
}

// findOrCreateRouter return an existing router that matches ip or create a new one if not found.
//
// The function will copy mac and ip if required. It is safe to call this using a frame buffer.
func (h *Handler6) findOrCreateRouter(mac net.HardwareAddr, ip netip.Addr) (router *Router, found bool) {
	r, found := h.LANRouters[ip]
	if found {
		return r, true
	}
	router = &Router{Addr: packet.Addr{MAC: packet.CopyMAC(mac), IP: ip}}
	h.LANRouters[ip] = router
	h.Router = router // make this the default ipv6 router - used in na attack
	fmt.Printf("icmp6 : create new ipv6 router %s\n", router)
	return router, false
}

func (h *Handler6) FindRouter(ip netip.Addr) Router {
	h.Mutex.Lock()
	r := h.LANRouters[ip]
	h.Mutex.Unlock()
	if r != nil {
		return *r
	}
	return Router{}
}

type RADVS struct {
	h           *Handler6
	Router      *Router
	stopChannel chan bool
}

func (h *Handler6) StartRADVS(managed bool, other bool, prefixes []packet.PrefixInformation, rdnss *packet.RecursiveDNSServer) (*RADVS, error) {
	return h.startRADVS(managed, other, prefixes, rdnss)
}

func (h *Handler6) startRADVS(managed bool, other bool, prefixes []packet.PrefixInformation, rdnss *packet.RecursiveDNSServer) (radvs *RADVS, err error) {
	radvs = &RADVS{stopChannel: make(chan bool, 1)}
	radvs.Router, _ = h.findOrCreateRouter(h.session.NICInfo.HostAddr4.MAC, h.session.NICInfo.HostLLA.Addr())
	radvs.Router.enableRADVS = true
	radvs.Router.ManagedFlag = managed
	radvs.Router.OtherCondigFlag = other
	radvs.Router.MTU = uint32(h.session.NICInfo.IFI.MTU)
	radvs.Router.ReacheableTime = int((time.Minute * 10).Milliseconds()) // Must be no greater than 3,600,000 milliseconds (1hour)
	radvs.Router.RetransTimer = int((time.Minute * 2).Milliseconds())
	radvs.Router.CurHopLimit = 1
	radvs.Router.DefaultLifetime = time.Minute * 30 // A value of zero means the router is not to be used as a default router
	radvs.Router.Prefixes = prefixes
	radvs.Router.RDNSS = rdnss
	radvs.h = h

	go radvs.sendAdvertistementLoop()

	return radvs, nil
}

func (r *RADVS) Stop() {
	r.stopChannel <- true
}

func (r *RADVS) SendRA() error {
	return r.h.session.ICMP6SendRouterAdvertisement(r.Router.Prefixes, r.Router.RDNSS, packet.IP6AllNodesAddr)
}

func (r *RADVS) sendAdvertistementLoop() {
	r.h.session.ICMP6SendRouterAdvertisement(r.Router.Prefixes, r.Router.RDNSS, packet.IP6AllNodesAddr)
	ticker := time.NewTicker(time.Duration(int64(time.Millisecond) * int64(r.Router.RetransTimer))).C
	for {
		select {
		case <-r.stopChannel:
			return

		case <-ticker:
			if err := r.h.session.ICMP6SendRouterAdvertisement(r.Router.Prefixes, r.Router.RDNSS, packet.IP6AllNodesAddr); err != nil {
				fmt.Printf("icmp6 : error in send ra: %s", err)
			}
		}
	}
}
