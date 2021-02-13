package icmp6

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/irai/packet"
	"github.com/irai/packet/raw"
	"github.com/mdlayher/netx/rfc4193"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv6"
)

// Debug packets turn on logging if desirable
var Debug bool

// Host holds a host identification
type Host struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Online   bool
	Router   bool
	LastSeen time.Time
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
	RDNSS           *RecursiveDNSServer
	Options         []Option
}

// Event represents and ICMP6 event from a host
type Event struct {
	Type ipv6.ICMPType
	Host Host
}

// PrintTable logs ICMP6 tables to standard out
func (h *Handler) PrintTable() {
	if len(h.LANHosts) > 0 {
		fmt.Printf("icmp6 hosts table len=%v\n", len(h.LANHosts))
		for _, v := range h.LANHosts {
			fmt.Printf("mac=%s ip=%v online=%v router=%v\n", v.MAC, v.IP, v.Online, v.Router)
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

func findOrCreateRouter(mac net.HardwareAddr, ip net.IP) (router *Router, found bool) {
	router = &Router{MAC: raw.CopyMAC(mac), IP: raw.CopyIP(ip)}
	return router, false
}

var ipv6LinkLocal = func(cidr string) *net.IPNet {
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return net
}("fe80::/10")

// GenerateULA creates a universal local address
// Usefule to create a IPv6 prefix when there is no global IPv6 routing
func GenerateULA(mac net.HardwareAddr, subnet uint16) (*net.IPNet, error) {
	prefix, err := rfc4193.Generate(mac)
	if err != nil {
		return nil, err
	}
	return prefix.Subnet(subnet).IPNet(), nil
}

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler struct {
	pc           *ipv6.PacketConn
	conn         net.PacketConn
	mutex        sync.Mutex
	ifi          *net.Interface
	notification chan<- Event
	Router       Router
	LANRouters   map[string]*Router
	LANHosts     map[string]*Host
}

// Config define server configuration values

var handler Handler

// New creates a new instance of ICMP6 on a given interface
func New(nic string) (*Handler, error) {
	var err error

	handler = Handler{LANRouters: make(map[string]*Router), LANHosts: make(map[string]*Host)}
	handler.ifi, err = net.InterfaceByName(nic)
	if err != nil {
		return nil, fmt.Errorf("interface not found nic=%s: %w", nic, err)
	}

	c, err := net.ListenPacket("ip6:1", "::") // ICMP for IPv6
	if err != nil {
		return nil, fmt.Errorf("error in ListenPacket: %w", err)
	}

	handler.pc = ipv6.NewPacketConn(c)

	return &handler, nil
}

// Close closes the underlying sockets
func (h *Handler) Close() error {
	if h.pc != nil {
		return h.pc.Close()
	}
	return nil
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

var repeat int

func (h *Handler) ProcessPacket(host *packet.Host, p []byte) error {

	// TODO: verify checksum?
	frame := raw.ICMP(p)
	if !frame.IsValid() {
		fmt.Println("error: packet invalid icmp ", frame)
		return fmt.Errorf("invalid icmp msg=%v: %w", frame, errParseMessage)
	}

	t := ipv6.ICMPType(p[0])
	switch t {
	case ipv6.ICMPTypeNeighborAdvertisement:
		msg := new(NeighborAdvertisement)
		if err := msg.unmarshal(p[icmpLen:]); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		fmt.Printf("icmp6 neighbor advertisement: %+v\n", msg)

	case ipv6.ICMPTypeNeighborSolicitation:
		msg := new(NeighborSolicitation)
		if err := msg.unmarshal(p[icmpLen:]); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		fmt.Printf("icmp6 neighbor solicitation: %+v\n", msg)

	case ipv6.ICMPTypeRouterAdvertisement:
		msg := new(RouterAdvertisement)
		if err := msg.unmarshal(p[icmpLen:]); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		if repeat%16 != 0 {
			fmt.Printf("icmp6 repeated router advertisement : \n")
			repeat++
			break
		}
		repeat++
		fmt.Printf("icmp6 router advertisement : %+v\n", msg)
		router, _ := findOrCreateRouter(host.MAC, host.IP)
		router.ManagedFlag = msg.ManagedConfiguration
		router.CurHopLimit = msg.CurrentHopLimit
		router.DefaultLifetime = msg.RouterLifetime
		router.Options = msg.Options
		host.ICMP6 = router

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
		if err := msg.unmarshal(p[icmpLen:]); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		fmt.Printf("icmp6 router solicitation: %+v\n", msg)

	case ipv6.ICMPTypeEchoReply:
		fmt.Printf("icmp6 echo reply: \n")
		msg := raw.ICMPEcho(p)
		if !msg.IsValid() {
			return fmt.Errorf("invalid icmp echo msg len=%d", len(p))
		}
		fmt.Printf("icmp6 echo msg: %s\n", msg)

	case ipv6.ICMPTypeEchoRequest:
		fmt.Printf("icmp6 echo request \n")
	default:
		log.Printf("icmp6 not implemented type=%v ip6=%s\n", t)
		return fmt.Errorf("ndp: unrecognized ICMPv6 type %d: %w", t, errParseMessage)
	}

	if h.notification != nil {
		go func() { h.notification <- Event{Type: t} }()
	}

	return nil
}

// ListenAndServe listend for raw ICMP6 packets and process packets
func (h *Handler) ListenAndServe(ctxt context.Context) (err error) {

	bpf, err := bpf.Assemble([]bpf.Instruction{
		// Check EtherType
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 80221Q?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_8021Q, SkipFalse: 1}, // EtherType is 2 pushed out by two bytes
		bpf.LoadAbsolute{Off: 14, Size: 2},
		// IPv6 && ICMPv6?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_IPV6, SkipFalse: 3},
		bpf.LoadAbsolute{Off: 14 + 6, Size: 1},                 // IPv6 Protocol field - 14 Eth bytes + 6 IPv6 header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipFalse: 1}, // ICMPv6 protocol - 58
		bpf.RetConstant{Val: 1540},                             // matches ICMPv6, accept up to 1540 (1500 payload + ether header)
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		log.Fatal("bpf assemble error", err)
	}

	h.conn, err = raw.ListenPacket(h.ifi, syscall.ETH_P_IPV6, raw.Config{Filter: bpf})
	if err != nil {
		h.conn = nil // on windows, not impleted returns a partially completed conn
		return fmt.Errorf("raw.ListenPacket error: %w", err)
	}
	defer h.conn.Close()

	buf := make([]byte, h.ifi.MTU)
	for {
		if err = h.conn.SetReadDeadline(time.Now().Add(time.Second * 2)); err != nil {
			if ctxt.Err() != context.Canceled {
				return fmt.Errorf("setReadDeadline error: %w", err)
			}
			return
		}

		n, _, err1 := h.conn.ReadFrom(buf)
		if err1 != nil {
			if err1, ok := err1.(net.Error); ok && err1.Temporary() {
				continue
			}
			if ctxt.Err() != context.Canceled {
				return fmt.Errorf("read error: %w", err1)
			}
			return
		}

		ether := raw.Ether(buf[:n])
		if ether.EtherType() != syscall.ETH_P_IPV6 || !ether.IsValid() {
			log.Error("icmp invalid ethernet packet ", ether.EtherType())
			continue
		}

		fmt.Println("icmp: got ipv6 packet type=", ether.EtherType())
	}
}
