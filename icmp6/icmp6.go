package icmp6

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/irai/packet"
	log "github.com/sirupsen/logrus"

	"golang.org/x/net/ipv6"
)

// Debug packets turn on logging if desirable
var Debug bool

// Router holds a router identification
type Router struct {
	MAC             net.HardwareAddr // LLA - Local link address
	IP              net.IP
	enableRADVS     bool // if true, we respond for this server
	ManagedFlag     bool // if true, hosts should get IP from DHCP, if false, use SLAAC IP
	OtherCondigFlag bool // if true, hosts should get other info from DHCP
	MTU             uint32
	ReacheableTime  int // Must be no greater than 3,600,000 milliseconds (1hour)
	RetransTimer    int //
	CurHopLimit     uint8
	DefaultLifetime time.Duration // A value of zero means the router is not to be used as a default router
	Prefixes        []PrefixInformation
	RDNSS           *RecursiveDNSServer // Pointer to facilitate comparison
	Options         NewOptions
}

// Event represents and ICMP6 event from a host
type Event struct {
	Type ipv6.ICMPType
	Host packet.Host
}

// PrintTable logs ICMP6 tables to standard out
func (h *Handler) PrintTable() {
	table := h.engine.GetHosts()
	if len(table) > 0 {
		fmt.Printf("icmp6 hosts table len=%v\n", len(table))
		for _, host := range table {
			host.Row.RLock()
			if packet.IsIP6(host.IP) {
				fmt.Printf("mac=%s ip=%v online=%v IP6router=%v\n", host.MACEntry.MAC, host.IP, host.Online, host.GetICMP6StoreNoLock())
			}
			host.Row.RUnlock()
		}
	}

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
	router = &Router{MAC: packet.CopyMAC(mac), IP: packet.CopyIP(ip)}
	h.LANRouters[string(ip)] = router
	return router, false
}

var _ packet.PacketProcessor = &Handler{}

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler struct {
	Router     Router
	LANRouters map[string]*Router
	engine     *packet.Handler
	closed     bool
	closeChan  chan bool
}

// Config define server configuration values
type Config struct {
	GlobalUnicastAddress net.IPNet
	LocalLinkAddress     net.IPNet
	UniqueLocalAddress   net.IPNet
}

// Attach creates an ICMP6 handler and attach to the engine
func Attach(engine *packet.Handler) (*Handler, error) {

	h := &Handler{LANRouters: make(map[string]*Router), closeChan: make(chan bool)}
	h.engine = engine
	engine.HandlerICMP6 = h

	return h, nil
}

// Detach removes the plugin from the engine
func (h *Handler) Detach() error {
	h.closed = true
	close(h.closeChan)
	h.engine.HandlerICMP6 = packet.PacketNOOP{}
	return nil
}

// Start prepares to accept packets
func (h *Handler) Start() error {
	if err := h.SendRouterSolicitation(); err != nil {
		return err
	}
	return packet.Ping(packet.IP6AllNodesMulticast) // ping with external cmd tool
	// return h.SendEchoRequest(packet.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostLLA.IP}, packet.IP6AllNodesAddr, 0, 0)
}

// Stop implements PacketProcessor interface
func (h *Handler) Stop() error {
	return nil
}

// MinuteTicker implements packet processor interface
func (h *Handler) MinuteTicker(now time.Time) error {
	return nil
}

// HuntStage implements PacketProcessor interface
func (h *Handler) CheckAddr(addr packet.Addr) (packet.HuntStage, error) {
	if err := h.Ping(packet.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostLLA.IP}, addr, time.Second*2); err != nil {
		return packet.StageNoChange, packet.ErrTimeout
	}
	return packet.StageNormal, nil
}

func (h *Handler) sendPacket(srcAddr packet.Addr, dstAddr packet.Addr, b []byte) error {
	ether := packet.Ether(make([]byte, packet.EthMaxSize)) // Ping is called many times concurrently by client

	hopLimit := uint8(64)
	if dstAddr.IP.IsLinkLocalUnicast() || dstAddr.IP.IsLinkLocalMulticast() {
		hopLimit = 1
	}

	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IPV6, srcAddr.MAC, dstAddr.MAC)
	ip6 := packet.IP6MarshalBinary(ether.Payload(), hopLimit, srcAddr.IP, dstAddr.IP)
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
	ICMP6(ip6.Payload()).SetChecksum(packet.Checksum(psh))

	// icmp6 := ICMP6(packet.IP6(ether.Payload()).Payload())
	// fmt.Println("DEBUG icmp :", icmp6, len(icmp6))
	// fmt.Println("DEBUG ether:", ether, len(ether), len(b))
	if _, err := h.engine.Conn().WriteTo(ether, &packet.Addr{MAC: dstAddr.MAC}); err != nil {
		log.Error("icmp failed to write ", err)
		return err
	}

	return nil
}

var repeat int = -1

// ProcessPacket handles icmp6 packets
func (h *Handler) ProcessPacket(host *packet.Host, b []byte) (*packet.Host, packet.Result, error) {

	ether := packet.Ether(b)
	ip6Frame := packet.IP6(ether.Payload())
	icmp6Frame := ICMP6(ip6Frame.Payload())

	if !icmp6Frame.IsValid() {
		return host, packet.Result{}, fmt.Errorf("invalid icmp msg=%v: %w", icmp6Frame, errParseMessage)
	}

	t := ipv6.ICMPType(icmp6Frame.Type())
	if Debug && t != ipv6.ICMPTypeRouterAdvertisement {
		fmt.Println("ether:", ether)
		fmt.Println("ip6  :", ip6Frame)
	}

	switch t {
	case ipv6.ICMPTypeNeighborAdvertisement:
		frame := ICMP6NeighborAdvertisement(icmp6Frame)
		if !frame.IsValid() {
			fmt.Println("icmp6 : invalid NS msg")
			return host, packet.Result{}, packet.ErrParseMessage
		}
		fmt.Printf("icmp6: neighbor advertisement %s\n", frame)

		// Source IP is sometimes ff02::1 multicast, which means the host is nil
		if host == nil {
			host, _ = h.engine.FindOrCreateHost(ether.Src(), frame.TargetAddress()) // will lock/unlock mutex
		}

	case ipv6.ICMPTypeNeighborSolicitation:
		frame := ICMP6NeighborSolicitation(icmp6Frame)
		if !frame.IsValid() {
			fmt.Println("icmp6 : invalid NS msg")
			return host, packet.Result{}, packet.ErrParseMessage
		}
		fmt.Printf("icmp6: neighbor solicitation %s\n", frame)

		// IPv6 Duplicate Address Detection
		// IP6 src=0x00 dst=solicited-node address (multicast)
		//
		if ip6Frame.Src().IsUnspecified() {
			fmt.Printf("icmp6: dad probe for target=%s srcip=%s srcmac=%s dstip=%s dstmac=%s\n", frame.TargetAddress(), ip6Frame.Src(), ether.Src(), ip6Frame.Dst(), ether.Dst())
			host, _ = h.engine.FindOrCreateHost(ether.Src(), frame.TargetAddress()) // will lock/unlock mutex
		}

	case ipv6.ICMPTypeRouterAdvertisement:

		frame := ICMP6RouterAdvertisement(icmp6Frame)
		if !frame.IsValid() {
			fmt.Println("icmp6 : invalid icmp6 ra msg")
			return host, packet.Result{}, packet.ErrParseMessage
		}

		repeat++
		if repeat%4 != 0 { // skip if too often - home router send RA every 4 sec
			break
		}

		// Protect agains nil host
		// NS source IP is sometimes ff02::1 (multicast), which means that host is not in the table (nil)
		if host == nil {
			return host, packet.Result{}, fmt.Errorf("ra host cannot be nil")
		}
		router, _ := h.findOrCreateRouter(host.MACEntry.MAC, host.IP)
		router.ManagedFlag = frame.ManagedConfiguration()
		router.CurHopLimit = frame.CurrentHopLimit()
		router.DefaultLifetime = time.Duration(time.Duration(frame.Lifetime()) * time.Second)
		var err error
		if router.Options, err = frame.Options(); err != nil {
			fmt.Printf("icmp6 : invalid options %s\n", err)
			return host, packet.Result{}, err
		}

		if Debug {
			fmt.Println("ether :", ether)
			fmt.Println("ip6   :", ip6Frame)
		}
		fmt.Printf("icmp6 : router advertisement %s %+v \n", frame, router.Options)

	case ipv6.ICMPTypeRouterSolicitation:
		frame := ICMP6RouterSolicitation(icmp6Frame)
		if !frame.IsValid() {
			return host, packet.Result{}, packet.ErrParseMessage
		}
		if Debug {
			fmt.Printf("icmp6 : router solicitation %s\n", frame)
		}
		/**
		for _, v := range h.LANRouters {
			if v.enableRADVS {
				if bytes.Equal(ether.Src(), msg.SourceLLA) {
					fmt.Printf("icmp6 error: source link address differ: ether=%s rs=%s\n", ether.Src(), ip6Frame.Src())
				}
				h.SendRouterAdvertisement(v, packet.Addr{MAC: ether.Src(), IP: ip6Frame.Src()})
			}
		}
		**/

	case ipv6.ICMPTypeEchoReply:
		echo := packet.ICMPEcho(icmp6Frame)
		if !echo.IsValid() {
			return host, packet.Result{}, fmt.Errorf("invalid icmp echo msg len=%d", len(icmp6Frame))
		}
		if Debug {
			fmt.Printf("icmp6: echo reply rcvd %s\n", echo)
		}
		echoNotify(echo.EchoID()) // unblock ping if waiting

	case ipv6.ICMPTypeEchoRequest:
		echo := packet.ICMPEcho(icmp6Frame)
		if Debug {
			fmt.Printf("icmp6: echo request rcvd%s\n", echo)
		}

	default:
		log.Printf("icmp6 not implemented type=%v ip6=%s\n", t, icmp6Frame)
		return host, packet.Result{}, fmt.Errorf("unrecognized icmp6 type %d: %w", t, errParseMessage)
	}

	return host, packet.Result{}, nil
}
