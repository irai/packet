package icmp6

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/irai/packet/raw"

	"golang.org/x/net/ipv6"
)

// Debug packets turn on logging if desirable
var Debug bool

type ICMP6Data struct {
	router *Router
}

// Router holds a router identification
type Router struct {
	MAC             net.HardwareAddr // LLA - Local link address
	IP              net.IP
	ManagedFlag     bool
	OtherCondigFlag bool
	MTU             uint32
	ReacheableTime  int // Must be no greater than 3,600,000 milliseconds (1hour)
	RetransTimer    int //
	CurHopLimit     uint8
	DefaultLifetime time.Duration // A value of zero means the router is not to be used as a default router
	Prefixes        []PrefixInformation
	RDNSS           *RecursiveDNSServer // Pointer to facilitate comparison
	Options         []Option
}

// Event represents and ICMP6 event from a host
type Event struct {
	Type ipv6.ICMPType
	Host raw.Host
}

// PrintTable logs ICMP6 tables to standard out
func (h *Handler) PrintTable() {
	// Important: Lock the global table
	h.LANHosts.Lock()
	defer h.LANHosts.Unlock()

	if len(h.LANHosts.Table) > 0 {
		fmt.Printf("icmp6 hosts table len=%v\n", len(h.LANHosts.Table))
		for _, v := range h.LANHosts.Table {
			if raw.IsIP6(v.IP) {
				fmt.Printf("mac=%s ip=%v online=%v IP6router=%v\n", v.MAC, v.IP, v.Online, v.IPV6Router)
			}
		}
	}

	// lock this handler
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if len(h.LANRouters) > 0 {
		fmt.Printf("icmp6 routers table len=%v\n", len(h.LANRouters))
		for _, v := range h.LANRouters {
			flags := ""
			if v.ManagedFlag {
				flags = flags + "M"
			}
			if v.OtherCondigFlag {
				flags = flags + "O"
			}
			fmt.Printf("mac=%s ip=%v flags=%s prefixes=%v rdnss=%+v options=%+v\n", v.MAC, v.IP, flags, v.Prefixes, v.RDNSS, v.Options)
		}
	}
}

func (h *Handler) findOrCreateRouter(mac net.HardwareAddr, ip net.IP) (router *Router, found bool) {
	r, found := h.LANRouters[string(ip)]
	if found {
		return r, true
	}
	router = &Router{MAC: raw.CopyMAC(mac), IP: raw.CopyIP(ip)}
	h.LANRouters[string(ip)] = router
	return router, false
}

// var _, _ raw.PacketProcessor = New(nil, nil)

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler struct {
	conn         net.PacketConn
	ifi          *net.Interface
	mutex        sync.Mutex
	notification chan<- Event
	Router       Router
	LANRouters   map[string]*Router
	LANHosts     *raw.HostTable
	ipNetGUA     net.IPNet // global unicast address
	ipNetLLA     net.IPNet // local link address
	ipNetULA     net.IPNet // unique local address (site wide)
}

// Config define server configuration values
type Config struct {
	GlobalUnicastAddress net.IPNet
	LocalLinkAddress     net.IPNet
	UniqueLocalAddress   net.IPNet
}

// New creates a new instance of ICMP6 on a given interface
func New(ifi *net.Interface, conn net.PacketConn, table *raw.HostTable, config Config) (*Handler, error) {

	h := &Handler{LANRouters: make(map[string]*Router), LANHosts: table}
	h.ipNetGUA = config.GlobalUnicastAddress
	h.ipNetLLA = config.LocalLinkAddress
	h.ipNetULA = config.UniqueLocalAddress
	h.ifi = ifi
	h.conn = conn

	return h, nil
}

func (h *Handler) Start(ctx context.Context) error {
	return nil
}

// Close closes the underlying sockets
func (h *Handler) Close() error {
	if h.conn != nil {
		return h.conn.Close()
	}
	return nil
}

func (h *Handler) LLA() net.IPNet {
	return h.ipNetLLA
}

// AddNotificationChannel set the notification channel for ICMP6 messages
func (h *Handler) AddNotificationChannel(notification chan<- Event) {
	h.notification = notification
}

func (h *Handler) autoConfigureRouter(router Router) {
	if len(h.Router.Prefixes) == 0 {
		h.Router = router

	}
}

func (h *Handler) sendPacket(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP, b []byte) error {

	hopLimit := uint8(64)
	if dstIP.IsLinkLocalUnicast() || dstIP.IsLinkLocalMulticast() {
		hopLimit = 1
	}

	ether := raw.EtherMarshalBinary(nil, syscall.ETH_P_IPV6, srcMAC, dstMAC)
	fmt.Println("DEBUG ether:", ether, len(ether), len(b))
	ip6 := raw.IP6MarshalBinary(ether.Payload(), hopLimit, srcIP, dstIP)
	fmt.Println("DEBUG ip6  :", raw.IP6(ether.Payload()))
	ip6, _ = ip6.AppendPayload(b, syscall.IPPROTO_ICMPV6)
	ether, _ = ether.SetPayload(ip6)

	// Calculate checksum of the pseudo header
	// The ICMPv6 checksum takes into account a pseudoheader of 40 bytes, which is a derivative of the real IPv6 header
	// which is composed as follows (in order):
	//   - 16 bytes for the source address
	//   - 16 bytes for the destination address
	//   - 4 bytes high endian payload length (the same value as in the IPv6 header)
	//   - 3 bytes zero
	//   - 1 byte nextheader (so, 58 decimal)
	psh := make([]byte, 40+len(b))
	copy(psh[0:16], ip6.Src())
	copy(psh[16:32], ip6.Dst())
	binary.BigEndian.PutUint32(psh[32:36], uint32(len(b)))
	psh[39] = 58
	copy(psh[40:], b)
	ICMP6(ip6.Payload()).SetChecksum(raw.Checksum(psh))

	icmp6 := ICMP6(raw.IP6(ether.Payload()).Payload())
	fmt.Println("DEBUG icmp :", icmp6, len(icmp6))
	fmt.Println("DEBUG ether:", ether, len(ether), len(b))
	if _, err := h.conn.WriteTo(ether, &raw.Addr{MAC: dstMAC}); err != nil {
		log.Error("icmp failed to write ", err)
		return err
	}

	return nil
}

var repeat int

func (h *Handler) ProcessPacket(host *raw.Host, b []byte) error {

	// retrieve or set store
	h.LANHosts.Lock()
	store, _ := host.ICMP6.(*ICMP6Data)
	if store == nil {
		store = &ICMP6Data{}
		host.ICMP6 = store
	}
	h.LANHosts.Unlock()

	ether := raw.Ether(b)
	ip6Frame := raw.IP6(ether.Payload())
	icmp6Frame := ICMP6(ip6Frame.Payload())

	if !icmp6Frame.IsValid() {
		fmt.Println("error: packet invalid icmp ", icmp6Frame)
		return fmt.Errorf("invalid icmp msg=%v: %w", icmp6Frame, errParseMessage)
	}
	fmt.Printf("icmp6: %s\n", icmp6Frame)

	t := ipv6.ICMPType(icmp6Frame.Type())
	switch t {
	case ipv6.ICMPTypeNeighborAdvertisement:
		msg := new(NeighborAdvertisement)
		if err := msg.unmarshal(icmp6Frame); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		fmt.Printf("icmp6: neighbor advertisement: %+v\n", msg)

	case ipv6.ICMPTypeNeighborSolicitation:
		msg := new(NeighborSolicitation)
		if err := msg.unmarshal(icmp6Frame); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		fmt.Printf("icmp6: neighbor solicitation: %+v\n", msg)

	case ipv6.ICMPTypeRouterAdvertisement:
		msg := new(RouterAdvertisement)
		if err := msg.unmarshal(icmp6Frame); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		if repeat%16 != 0 {
			fmt.Printf("icmp6 repeated router advertisement : \n")
			repeat++
			break
		}
		repeat++
		fmt.Printf("icmp6: router advertisement : %+v\n", msg)
		router, _ := h.findOrCreateRouter(host.MAC, host.IP)
		router.ManagedFlag = msg.ManagedConfiguration
		router.CurHopLimit = msg.CurrentHopLimit
		router.DefaultLifetime = msg.RouterLifetime
		router.Options = msg.Options

		// update router details in host
		h.LANHosts.Lock()
		host.IPV6Router = true
		h.LANHosts.Unlock()

		prefixes := []PrefixInformation{}
		for _, v := range msg.Options {
			switch v.Code() {
			case optMTU:
				o := v.(*MTU)
				fmt.Println(" options mtu ", v.Code(), o)
				router.MTU = uint32(*o)
			case optPrefixInformation:
				o := v.(*PrefixInformation)
				fmt.Println(" options prefix ", v.Code(), o)
				prefixes = append(prefixes, *o)
			case optRDNSS:
				o := v.(*RecursiveDNSServer)
				fmt.Println(" options RDNSS ", v.Code(), o)
				router.RDNSS = o
			case optSourceLLA:
				o := v.(*LinkLayerAddress)
				fmt.Println(" options LLA ", v.Code(), o)
				if !bytes.Equal(o.Addr, host.MAC) {
					log.Printf("error: icmp6 unexpected sourceLLA=%s etherFrame=%s", o.Addr, host.MAC)
				}
			}
		}

		if len(prefixes) > 0 {
			router.Prefixes = prefixes
			if len(prefixes) > 1 {
				fmt.Printf("error: icmp6 invalid prefix list len=%d list=%v", len(prefixes), prefixes)
			}

			h.autoConfigureRouter(*router)
		}

	case ipv6.ICMPTypeRouterSolicitation:
		msg := new(RouterSolicitation)
		if err := msg.unmarshal(icmp6Frame); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		fmt.Printf("icmp6 router solicitation: %+v\n", msg)

	case ipv6.ICMPTypeEchoReply:
		msg := raw.ICMPEcho(icmp6Frame)
		if !msg.IsValid() {
			return fmt.Errorf("invalid icmp echo msg len=%d", len(icmp6Frame))
		}
		fmt.Printf("icmp6: echo reply %s\n", msg)

	case ipv6.ICMPTypeEchoRequest:
		msg := raw.ICMPEcho(icmp6Frame)
		fmt.Printf("icmp6: echo request %s\n", msg)

	default:
		log.Printf("icmp6 not implemented type=%v ip6=%s\n", t, icmp6Frame)
		return fmt.Errorf("ndp: unrecognized ICMPv6 type %d: %w", t, errParseMessage)
	}

	if h.notification != nil {
		go func() { h.notification <- Event{Type: t} }()
	}

	return nil
}
