package icmp_spoofer

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"

	"golang.org/x/net/ipv6"
)

var Logger4 = fastlog.New("icmp4")
var Logger6 = fastlog.New("icmp4")

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler6 struct {
	Router     *Router
	LANRouters map[netip.Addr]*Router
	session    *packet.Session
	huntList   packet.AddrList
	closed     bool
	closeChan  chan bool
	sync.Mutex
}

// PrintTable logs ICMP6 tables to standard out
func (h *Handler6) PrintTable() {
	table := h.session.GetHosts()
	if len(table) > 0 {
		fmt.Printf("icmp6 hosts table len=%v\n", len(table))
		for _, host := range table {
			host.MACEntry.Row.RLock()
			if host.Addr.IP.Is6() {
				fmt.Printf("mac=%s ip=%v online=%v \n", host.MACEntry.MAC, host.Addr.IP, host.Online)
			}
			host.MACEntry.Row.RUnlock()
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
			fmt.Printf("%s flags=%s prefixes=%v rdnss=%+v options=%+v\n", v.Addr, flags, v.Prefixes, v.RDNSS, v.Options)
		}
	}
}

// New creates an ICMP6 handler
func New6(session *packet.Session) (*Handler6, error) {
	h := &Handler6{LANRouters: make(map[netip.Addr]*Router), closeChan: make(chan bool)}
	h.session = session
	return h, nil
}

// Close releases underlying resources.
// The handler is not longer usable after calling Close().
func (h *Handler6) Close() error {
	if h.closed {
		return nil
	}
	h.closed = true
	close(h.closeChan)
	return nil
}

// PingAll sends an echo request to the IPv6 multicast address to
// encourage hosts to reply.
func (h *Handler6) PingAll() error {
	if !h.session.NICInfo.HostLLA.Addr().IsValid() {
		return packet.ErrInvalidIP6LLA
	}
	if Logger6.IsInfo() {
		Logger6.Msg("sending icmp6 ping all")
	}
	if err := h.session.ICMP6SendRouterSolicitation(); err != nil {
		return err
	}
	// if err := packet.ExecPing(packet.IP6AllNodesMulticast.String() + "%" + h.session.NICInfo.IFI.Name); err != nil { // ping with external cmd tool
	// fmt.Printf("icmp6 : error in initial ping all nodes multicast - ignoring : %s\n", err)
	// }
	return h.session.ICMP6SendEchoRequest(packet.Addr{MAC: h.session.NICInfo.HostAddr4.MAC, IP: h.session.NICInfo.HostLLA.Addr()}, packet.IP6AllNodesAddr, 99, 1)
}

var repeat int = -1

// ProcessPacket handles icmp6 packets and executes neighbor
// advertising spoofing for target LLAs.
func (h *Handler6) ProcessPacket(pkt packet.Frame) (err error) {
	ip6Frame := pkt.IP6()
	icmp6Frame := packet.ICMP(pkt.Payload())

	if err := icmp6Frame.IsValid(); err != nil {
		Logger6.Msg("error invalid icmp frame").ByteArray("frame", pkt.Payload()).Error(err).Write()
		return err
	}

	t := ipv6.ICMPType(icmp6Frame.Type())
	if Logger6.IsDebug() && t != ipv6.ICMPTypeRouterAdvertisement {
		Logger6.Msg("ether").Struct(pkt.Ether()).Module("icmp6", "ip6").Struct(ip6Frame).Module("icmp6", "icmp").Struct(icmp6Frame).Write()
	}

	switch t {
	case ipv6.ICMPTypeNeighborAdvertisement: // 0x88
		frame := packet.ICMP6NeighborAdvertisement(icmp6Frame)
		if err := frame.IsValid(); err != nil {
			fmt.Println("icmp6 : invalid NS msg", err)
			return err
		}
		if Logger6.IsDebug() {
			Logger6.Msg("neighbor advertisement rcvd").IP("ip", ip6Frame.Src()).Struct(frame).Write()
		}

		// When a device gets an IPv6 address, it will join a solicited-node multicast group
		// to see if any other devices are trying to communicate with it. In this case, the
		// source IP is sometimes ff02::1 multicast, which means the host is nil.
		// If unsolicited and Override, it is an indication the IPv6 that corresponds to a link layer address has changed.
		if frame.Override() && !frame.Solicited() {
			if Logger6.IsDebug() {
				Logger6.Msg("neighbor advertisement overrid IP").Struct(ip6Frame).Module("icmp6", "neighbour advertisement").Struct(frame).Write()
			}
			if frame.TargetLLA() == nil {
				Logger6.Msg("error NA override with nil targetLLA").Error(packet.ErrInvalidMAC).Write()
				return packet.ErrInvalidMAC
			}
		}

	case ipv6.ICMPTypeNeighborSolicitation: // 0x87
		frame := packet.ICMP6NeighborSolicitation(icmp6Frame)
		if err := frame.IsValid(); err != nil {
			return err
		}
		if Logger6.IsDebug() {
			Logger6.Msg("neighbor solicitation rcvd").IP("ip", ip6Frame.Src()).Struct(frame).Write()
		}

		// Source address:
		//   - Either an address assigned to the interface from which this message was sent or
		//     the unspecified address (if duplicated address detection in progress).
		// Destination address:
		//   - Either the solicited-node multicast address (ff02::1..) corresponding to the target address, or
		//     the target address.
		//
		//IPv6 Duplicate Address Detection
		// IP6 src=0x00 dst=solicited-node address (multicast)
		//
		if ip6Frame.Src().IsUnspecified() {
			if Logger6.IsDebug() {
				fmt.Printf("icmp6 : dad probe for target=%s srcip=%s srcmac=%s dstip=%s dstmac=%s\n", frame.TargetAddress(), ip6Frame.Src(), pkt.Ether().Src(), ip6Frame.Dst(), pkt.Ether().Dst())
			}
			return nil
		}

		// If a host is looking up for a GUA on the lan, it is likely a valid IP6 GUA for a local host.
		// So, send our own neighbour solicitation to discover the IP
		if frame.TargetAddress().IsGlobalUnicast() {
			srcAddr := packet.Addr{MAC: h.session.NICInfo.HostAddr4.MAC, IP: h.session.NICInfo.HostLLA.Addr()}
			dstAddr := packet.Addr{MAC: pkt.Ether().Dst(), IP: ip6Frame.Dst()}
			h.session.ICMP6SendNeighbourSolicitation(srcAddr, dstAddr, frame.TargetAddress())
		}
		return nil

	case ipv6.ICMPTypeRouterAdvertisement: // 0x86
		frame := packet.ICMP6RouterAdvertisement(icmp6Frame)
		if err := frame.IsValid(); err != nil {
			return err
		}

		// wakeup all pending spoof goroutines
		// we want to immediately spoof hosts after an RA
		if h.huntList.Len() > 0 {
			ch := h.closeChan
			h.closeChan = make(chan bool)
			close(ch) // this will cause all spoof loop select to wakeup
		}

		repeat++
		if repeat%4 != 0 { // skip if too often - home router send RA every 4 sec
			break
		}

		// Protect agains nil host
		// NS source IP is sometimes ff02::1 (multicast), which means that host is not in the table (nil)
		if pkt.Host == nil {
			return fmt.Errorf("ra host cannot be nil")
		}
		options, err := frame.Options()
		if err != nil {
			fmt.Printf("icmp6 : invalid options %s\n", err)
			return err
		}

		mac := options.SourceLLA.MAC
		if mac == nil || len(mac) != packet.EthAddrLen {
			mac = pkt.Ether().Src()
			fmt.Printf("icmp6 : options missing sourceLLA options=%v\n", options)
		}

		h.Lock()
		router, _ := h.findOrCreateRouter(mac, ip6Frame.Src())
		router.ManagedFlag = frame.ManagedConfiguration()
		router.OtherCondigFlag = frame.OtherConfiguration()
		router.Preference = frame.Preference()
		router.CurHopLimit = frame.CurrentHopLimit()
		router.DefaultLifetime = time.Duration(time.Duration(frame.Lifetime()) * time.Second)
		router.ReacheableTime = int(frame.ReachableTime())
		router.RetransTimer = int(frame.RetransmitTimer())
		// curPrefix := router.Options.FirstPrefix // keep current prefix
		router.Options = options
		router.Prefixes = options.Prefixes
		h.Unlock()

		if Logger6.IsDebug() {
			l := Logger6.Msg("ether").Struct(pkt.Ether()).Module("icmp6", "ip6").Struct(ip6Frame)
			l.Module("icmp6", "router advertisement").Struct(icmp6Frame).Sprintf("options", router.Options)
			l.Write()
		}
		return nil

	case ipv6.ICMPTypeRouterSolicitation:
		frame := packet.ICMP6RouterSolicitation(icmp6Frame)
		if err := frame.IsValid(); err != nil {
			return err
		}
		if Logger6.IsDebug() {
			Logger6.Msg("router solicitation").IP("ip", ip6Frame.Src()).Struct(frame).Write()
		}

		// Source address:
		//    - usually the unspecified IPv6 address (0:0:0:0:0:0:0:0) or
		//      configured unicast address of the interface.
		// Destination address:
		//    - the all-routers multicast address (FF02::2) with the link-local scope.
		return nil

	case ipv6.ICMPTypeEchoReply: // 0x81
		echo := packet.ICMPEcho(icmp6Frame)
		if err := echo.IsValid(); err != nil {
			return err
		}
		if Logger6.IsDebug() {
			fmt.Printf("icmp6 : echo reply recvd from ip=%s %s\n", ip6Frame.Src(), echo)
		}
		return nil

	case ipv6.ICMPTypeEchoRequest: // 0x80
		echo := packet.ICMPEcho(icmp6Frame)
		if Logger6.IsDebug() {
			Logger6.Msg("echo req recvd").IP("srcIP", ip6Frame.Src()).IP("dstIP", ip6Frame.Dst()).Struct(echo).Write()
		}
		return nil

	case ipv6.ICMPTypeMulticastListenerReport:
		if Logger6.IsDebug() {
			Logger6.Msg("multicast listener report recv").IP("ip", ip6Frame.Src()).Write()
		}
		return nil

	case ipv6.ICMPTypeVersion2MulticastListenerReport:
		if Logger6.IsDebug() {
			Logger6.Msg("multicast listener report V2 recv").IP("ip", ip6Frame.Src()).Write()
		}
		return nil

	case ipv6.ICMPTypeMulticastListenerQuery:
		if Logger6.IsDebug() {
			Logger6.Msg("multicast listener query recv").IP("ip", ip6Frame.Src()).Write()
		}
		return nil

	case ipv6.ICMPTypeRedirect:
		redirect := packet.ICMP6Redirect(icmp6Frame)
		if err := redirect.IsValid(); err != nil {
			return err
		}
		if Logger6.IsDebug() {
			Logger6.Msg("redirect recv").IP("fromIP", ip6Frame.Src()).Stringer(redirect).Write()
		}

		return nil

	case ipv6.ICMPTypeDestinationUnreachable:
		if Logger6.IsDebug() {
			Logger6.Msg("destination unreachable").Struct(ip6Frame).Struct(icmp6Frame).Write()
		}
		return nil

	default:
		fmt.Printf("icmp6 : type not implemented from ip=%s type=%v\n", ip6Frame.Src(), t)
		return fmt.Errorf("unrecognized icmp6 type=%d: %w", t, packet.ErrParseFrame)
	}

	return nil
}
