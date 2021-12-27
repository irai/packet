package icmp

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
	"inet.af/netaddr"

	"golang.org/x/net/ipv6"
)

// Debug turn on logging
var Debug bool

const module4 = "icmp4"
const module6 = "icmp6"

// Event represents and ICMP6 event from a host
type Event struct {
	Type ipv6.ICMPType
	Host packet.Host
}

type ICMP6Handler interface {
	FindRouter(net.IP) Router
	PingAll() error
	Start() error
	Close() error
	Spoof(frame packet.Frame) error
	StartHunt(packet.Addr) (packet.HuntStage, error)
	StopHunt(packet.Addr) (packet.HuntStage, error)
	CheckAddr(packet.Addr) (packet.HuntStage, error)
	MinuteTicker(time.Time) error
}
type ICMP6NOOP struct{}

func (p ICMP6NOOP) Start() error   { return nil }
func (p ICMP6NOOP) PingAll() error { return nil }
func (p ICMP6NOOP) Spoof(packet.Frame) error {
	return nil
}
func (p ICMP6NOOP) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	return packet.StageNoChange, nil
}
func (p ICMP6NOOP) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	return packet.StageNoChange, nil
}
func (p ICMP6NOOP) CheckAddr(addr packet.Addr) (packet.HuntStage, error) {
	return packet.StageNoChange, nil
}
func (p ICMP6NOOP) Close() error                     { return nil }
func (p ICMP6NOOP) MinuteTicker(now time.Time) error { return nil }
func (p ICMP6NOOP) FindRouter(net.IP) Router         { return Router{} }

var _ ICMP6Handler = &Handler6{}
var _ ICMP6Handler = &ICMP6NOOP{}

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler6 struct {
	Router     *Router
	LANRouters map[netaddr.IP]*Router
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
			if packet.IsIP6(host.Addr.IP) {
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

// Config define server configuration values
type Config struct {
	GlobalUnicastAddress net.IPNet
	LocalLinkAddress     net.IPNet
	UniqueLocalAddress   net.IPNet
}

// New creates an ICMP6 handler and attach to the engine
func New6(session *packet.Session) (*Handler6, error) {

	h := &Handler6{LANRouters: make(map[netaddr.IP]*Router), closeChan: make(chan bool)}
	h.session = session

	return h, nil
}

// Close removes the plugin from the engine
func (h *Handler6) Close() error {
	if h.closed {
		return nil
	}
	h.closed = true
	close(h.closeChan)
	return nil
}

// Start prepares to accept packets
func (h *Handler6) Start() error {
	if err := h.session.ICMP6SendRouterSolicitation(); err != nil {
		return err
	}
	if err := ExecPing(packet.IP6AllNodesMulticast.String() + "%" + h.session.NICInfo.IFI.Name); err != nil { // ping with external cmd tool
		fmt.Printf("icmp6 : error in initial ping all nodes multicast - ignoring : %s\n", err)
	}
	return nil
}

func (h *Handler6) PingAll() error {
	if h.session.NICInfo.HostLLA.IP == nil {
		return packet.ErrInvalidIP6LLA
	}
	fmt.Println("icmp6 : ping all")
	return h.session.ICMP6SendEchoRequest(packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostLLA.IP}, packet.IP6AllNodesAddr, 99, 1)
}

// MinuteTicker implements packet processor interface
// Send echo request to all nodes
func (h *Handler6) MinuteTicker(now time.Time) error {
	return h.session.ICMP6SendEchoRequest(packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostLLA.IP}, packet.IP6AllNodesAddr, 199, 1)
}

// HuntStage implements PacketProcessor interface
func (h *Handler6) CheckAddr(addr packet.Addr) (packet.HuntStage, error) {
	if h.session.NICInfo.HostLLA.IP == nil { // in case host does not have IPv6
		return packet.StageNoChange, nil
	}
	srcAddr := packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostLLA.IP}

	// Neigbour solicitation almost always result in a response from host if online unless
	// host is on battery saving mode
	if addr.IP.IsLinkLocalUnicast() {
		if err := h.session.ICMP6SendNeighbourSolicitation(srcAddr, packet.IPv6SolicitedNode(addr.IP), addr.IP); err != nil {
			fmt.Printf("icmp6 : error checking address %s error=\"%s\"", addr, err)
		}
		return packet.StageNoChange, nil
	}

	// ping response is optional and could be disabled on a given host
	if err := h.Ping(srcAddr, addr, time.Second*2); err != nil {
		return packet.StageNoChange, packet.ErrTimeout
	}

	return packet.StageNormal, nil
}

var repeat int = -1

// ProcessPacket handles icmp6 packets
func (h *Handler6) Spoof(pkt packet.Frame) (err error) {

	// ether := packet.Ether(p)
	ip6Frame := pkt.IP6()
	icmp6Frame := packet.ICMP(pkt.Payload())

	if err := icmp6Frame.IsValid(); err != nil {
		fastlog.NewLine(module6, "error invalid icmp frame").ByteArray("frame", pkt.Payload()).Error(err).Write()
		return err
	}

	t := ipv6.ICMPType(icmp6Frame.Type())
	if Debug && t != ipv6.ICMPTypeRouterAdvertisement {
		fastlog.NewLine("icmp6", "ether").Struct(pkt.Ether).Module("icmp6", "ip6").Struct(ip6Frame).Module("icmp6", "icmp").Struct(icmp6Frame).Write()
	}

	switch t {
	case ipv6.ICMPTypeNeighborAdvertisement: // 0x88
		frame := packet.ICMP6NeighborAdvertisement(icmp6Frame)
		if err := frame.IsValid(); err != nil {
			fmt.Println("icmp6 : invalid NS msg", err)
			return err
		}
		if Debug {
			fastlog.NewLine("icmp6", "neighbor advertisement").IP("ip", ip6Frame.Src()).Struct(frame).Write()
			// fastlog.Strings("icmp6 : neighbor advertisement from ip=", ip6Frame.Src().String(), " ", frame.String())
		}

		// When a device gets an IPv6 address, it will join a solicited-node multicast group
		// to see if any other devices are trying to communicate with it. In this case, the
		// source IP is sometimes ff02::1 multicast, which means the host is nil.
		// If unsolicited and Override, it is an indication the IPv6 that corresponds to a link layer address has changed.
		if frame.Override() && !frame.Solicited() {
			fastlog.NewLine(module6, "neighbor advertisement overrid IP").Struct(ip6Frame).Module(module6, "neighbour advertisement").Struct(frame).Write()
			if frame.TargetLLA() == nil {
				fastlog.NewLine(module6, "error na override with nil targetLLA").Error(packet.ErrInvalidMAC).Write()
				return packet.ErrInvalidMAC
			}
			// result.Update = true
			// result.SrcAddr = packet.Addr{MAC: frame.TargetLLA(), IP: frame.TargetAddress()
		}

	case ipv6.ICMPTypeNeighborSolicitation: // 0x87
		frame := packet.ICMP6NeighborSolicitation(icmp6Frame)
		if err := frame.IsValid(); err != nil {
			return err
		}
		if Debug {
			fastlog.NewLine("icmp6", "neighbor solicitation").IP("ip", ip6Frame.Src()).Struct(frame).Write()
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
			if Debug {
				fmt.Printf("icmp6 : dad probe for target=%s srcip=%s srcmac=%s dstip=%s dstmac=%s\n", frame.TargetAddress(), ip6Frame.Src(), pkt.Ether.Src(), ip6Frame.Dst(), pkt.Ether.Dst())
			}
			// result.Update = true
			// result.SrcAddr = packet.Addr{MAC: ether.Src(), IP: frame.TargetAddress()} // ok to pass frame addr
			return nil
		}

		// If a host is looking up for a GUA on the lan, it is likely a valid IP6 GUA for a local host.
		// So, send our own neighbour solicitation to discover the IP
		if frame.TargetAddress().IsGlobalUnicast() {
			srcAddr := packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostLLA.IP}
			dstAddr := packet.Addr{MAC: pkt.Ether.Dst(), IP: ip6Frame.Dst()}
			h.session.ICMP6SendNeighbourSolicitation(srcAddr, dstAddr, frame.TargetAddress())
		}
		return nil

	case ipv6.ICMPTypeRouterAdvertisement: // 0x86
		frame := packet.ICMP6RouterAdvertisement(icmp6Frame)
		if err := frame.IsValid(); err != nil {
			return err
		}

		// wakeup all pending spoof goroutines
		// we want to immediately spoof hosts after a RA
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
			mac = pkt.Ether.Src()
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

		if Debug {
			l := fastlog.NewLine("icmp6", "ether").Struct(pkt.Ether).Module("icmp6", "ip6").Struct(ip6Frame)
			l.Module("icmp6", "router advertisement").Struct(icmp6Frame).Sprintf("options", router.Options)
			l.Write()
		}

		// result := packet.Result{}
		//notify if first time or if prefix changed
		// if !found || !curPrefix.Equal(router.Options.FirstPrefix) {
		// result = packet.Result{Update: true, IsRouter: true}
		// }
		return nil

	case ipv6.ICMPTypeRouterSolicitation:
		frame := packet.ICMP6RouterSolicitation(icmp6Frame)
		if err := frame.IsValid(); err != nil {
			return err
		}
		if Debug {
			fastlog.NewLine("icmp6", "router solicitation").IP("ip", ip6Frame.Src()).Struct(frame).Write()
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
		if Debug {
			fmt.Printf("icmp6 : echo reply from ip=%s %s\n", ip6Frame.Src(), echo)
		}
		echoNotify(echo.EchoID()) // unblock ping if waiting
		return nil

	case ipv6.ICMPTypeEchoRequest: // 0x80
		echo := packet.ICMPEcho(icmp6Frame)
		if Debug {
			// fmt.Printf("icmp6 : echo request from ip=%s %s\n", ip6Frame.Src(), echo)
			fastlog.NewLine(module6, "echo recvd").IP("srcIP", ip6Frame.Src()).IP("dstIP", ip6Frame.Dst()).Struct(echo).Write()
		}
		return nil

	case ipv6.ICMPTypeMulticastListenerReport:
		fastlog.NewLine(module6, "multicast listener report recv").IP("ip", ip6Frame.Src()).Write()
		return nil

	case ipv6.ICMPTypeVersion2MulticastListenerReport:
		fastlog.NewLine(module6, "multicast listener report V2 recv").IP("ip", ip6Frame.Src()).Write()
		return nil

	case ipv6.ICMPTypeMulticastListenerQuery:
		fastlog.NewLine(module6, "multicast listener query recv").IP("ip", ip6Frame.Src()).Write()
		return nil

	case ipv6.ICMPTypeRedirect:
		redirect := packet.ICMP6Redirect(icmp6Frame)
		if err := redirect.IsValid(); err != nil {
			return err
		}
		// fmt.Printf("icmp6 : redirect from ip=%s %s \n", ip6Frame.Src(), redirect)
		fastlog.NewLine(module6, "redirect recv").IP("fromIP", ip6Frame.Src()).Stringer(redirect).Write()

		return nil

	case ipv6.ICMPTypeDestinationUnreachable:
		if Debug {
			fastlog.NewLine(module6, "destination unreachable").Struct(ip6Frame).Struct(icmp6Frame).Write()
		}
		return nil

	default:
		fmt.Printf("icmp6 : type not implemented from ip=%s type=%v\n", ip6Frame.Src(), t)
		return fmt.Errorf("unrecognized icmp6 type=%d: %w", t, packet.ErrParseFrame)
	}

	return nil
}
