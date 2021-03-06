package packet

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"
)

// Debug packets turn on logging if desirable
var (
	Debug    bool
	DebugIP6 bool
	DebugIP4 bool
	DebugUDP bool
)

// Config has a list of configurable parameters that overide package defaults
type Config struct {

	// Conn enables the client to override the connection with a another packet conn
	// usefule for testing
	Conn                    net.PacketConn // listen connectinon
	NICInfo                 *NICInfo       // override nic information
	FullNetworkScanInterval time.Duration  // Set it to zero if no scan required
	ProbeInterval           time.Duration  // how often to probe if IP is online
	OfflineDeadline         time.Duration  // mark offline if more than OfflineInte
	PurgeDeadline           time.Duration
}

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler struct {
	NICInfo                 *NICInfo
	conn                    net.PacketConn
	LANHosts                *HostTable
	HandlerIP4              PacketProcessor
	HandlerIP6              PacketProcessor
	HandlerICMP4            PacketProcessor
	HandlerICMP6            PacketProcessor
	HandlerDHCP4            PacketProcessor
	HandlerARP              PacketProcessor
	callback                []func(Notification) error
	captureList             *SetHandler
	FullNetworkScanInterval time.Duration // Set it to -1 if no scan required
	ProbeInterval           time.Duration // how often to probe if IP is online
	OfflineDeadline         time.Duration // mark offline if no updates
	PurgeDeadline           time.Duration // purge entry if no updates
	closed                  bool          // set to true when handler is closed
	sync.Mutex
}

// PacketNOOP is a no op packet processor
type PacketNOOP struct{}

var _ PacketProcessor = PacketNOOP{}

func (p PacketNOOP) Start() error                               { return nil }
func (p PacketNOOP) Stop() error                                { return nil }
func (p PacketNOOP) ProcessPacket(*Host, []byte) (*Host, error) { return nil, nil }
func (p PacketNOOP) StartHunt(net.HardwareAddr) error           { return nil }
func (p PacketNOOP) StopHunt(net.HardwareAddr) error            { return nil }

// New creates an ICMPv6 handler with default values
func NewEngine(nic string) (*Handler, error) {
	return Config{}.NewEngine(nic)
}

// NewEngine creates an packet handler with config values
func (config Config) NewEngine(nic string) (*Handler, error) {

	var err error

	h := &Handler{LANHosts: New(), captureList: &SetHandler{}}

	h.NICInfo = config.NICInfo
	if h.NICInfo == nil {
		h.NICInfo, err = GetNICInfo(nic)
		if err != nil {
			return nil, fmt.Errorf("interface not found nic=%s: %w", nic, err)
		}
	}

	h.FullNetworkScanInterval = config.FullNetworkScanInterval
	if h.FullNetworkScanInterval != -1 && (h.FullNetworkScanInterval <= 0 || h.FullNetworkScanInterval > time.Hour*12) {
		h.FullNetworkScanInterval = time.Minute * 60
	}
	h.ProbeInterval = config.ProbeInterval
	if h.ProbeInterval <= 0 || h.ProbeInterval > time.Minute*10 {
		h.ProbeInterval = time.Minute * 2
	}
	h.OfflineDeadline = config.OfflineDeadline
	if h.OfflineDeadline <= h.ProbeInterval {
		h.OfflineDeadline = h.ProbeInterval * 2
	}
	h.PurgeDeadline = config.PurgeDeadline
	if h.PurgeDeadline <= h.OfflineDeadline {
		h.PurgeDeadline = time.Minute * 61
	}

	// Skip if conn is overriden
	h.conn = config.Conn
	if h.conn == nil {
		h.conn, err = h.setupConn()
		if err != nil {
			return nil, err
		}
	}

	// no plugins to start
	h.HandlerARP = PacketNOOP{}
	h.HandlerIP4 = PacketNOOP{}
	h.HandlerIP6 = PacketNOOP{}
	h.HandlerARP = PacketNOOP{}
	h.HandlerICMP4 = PacketNOOP{}
	h.HandlerICMP6 = PacketNOOP{}
	h.HandlerDHCP4 = PacketNOOP{}

	return h, nil
}

// Close closes the underlying sockets
func (h *Handler) Close() error {
	if Debug {
		fmt.Println("packet: close() called. closing....")
	}
	h.closed = true
	h.conn.Close()
	return nil
}

// Conn return the underlying raw socket conn
func (h *Handler) Conn() net.PacketConn {
	return h.conn
}

func (h *Handler) setupConn() (conn net.PacketConn, err error) {

	// see syscall constants for full list of available network protocols
	// https://golang.org/pkg/syscall/
	//
	// For a list of bpf instructions
	// https://tshark.dev/packetcraft/arcana/bpf_instructions/
	//
	// TODO: Set direction - aparently this only works on bsd
	// https://github.com/google/gopacket/blob/master/pcap/pcap.go
	// https://github.com/mdlayher/raw/blob/master/raw.go
	//
	// TODO: use zero copy in bpf
	// https://www.gsp.com/cgi-bin/man.cgi?topic=BPF
	bpf, err := bpf.Assemble([]bpf.Instruction{
		// Check EtherType
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 80221Q? Virtual LAN over 802.3 Ethernet
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_8021Q, SkipFalse: 1}, // EtherType is 2 pushed out by two bytes
		bpf.LoadAbsolute{Off: 14, Size: 2},
		// IPv4?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_IP, SkipFalse: 1},
		bpf.RetConstant{Val: EthMaxSize},
		// IPv6?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_IPV6, SkipFalse: 1},
		bpf.RetConstant{Val: EthMaxSize},
		// ARP?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_ARP, SkipFalse: 1},
		bpf.RetConstant{Val: EthMaxSize},
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		log.Fatal("bpf assemble error", err)
	}

	// see: https://www.man7.org/linux/man-pages/man7/packet.7.html
	conn, err = NewServerConn(h.NICInfo.IFI, syscall.ETH_P_ALL, SocketConfig{Filter: bpf})
	if err != nil {
		return nil, fmt.Errorf("packet.ListenPacket error: %w", err)
	}

	// don't timeout during write
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return conn, nil
}

func (h *Handler) PrintTable() {
	h.LANHosts.PrintTable()
}

// isUnicastMAC return true if the mac address is unicast
//
// Bit 0 in the first octet is reserved for broadcast or multicast traffic.
// When we have unicast traffic this bit will be set to 0.
// For broadcast or multicast traffic this bit will be set to 1.
func isUnicastMAC(mac net.HardwareAddr) bool {
	if mac[0]&0x01 == 0x00 {
		return true
	}
	return false
}

func (h *Handler) startPlugins() error {
	time.Sleep(time.Millisecond * 200) // wait for read to start

	if err := h.HandlerIP4.Start(); err != nil {
		fmt.Println("error: in IP4 start:", err)
	}
	if err := h.HandlerIP6.Start(); err != nil {
		fmt.Println("error: in IP6 start:", err)
	}
	if err := h.HandlerICMP4.Start(); err != nil {
		fmt.Println("error: in ICMP4 start:", err)
	}
	if err := h.HandlerICMP6.Start(); err != nil {
		fmt.Println("error: in ICMP6 start:", err)
	}
	if err := h.HandlerARP.Start(); err != nil {
		fmt.Println("error: in ARP start:", err)
	}
	if err := h.HandlerDHCP4.Start(); err != nil {
		fmt.Println("error: in DHCP4 start:", err)
	}
	return nil
}

func (h *Handler) stopPlugins() error {
	if err := h.HandlerIP4.Stop(); err != nil {
		fmt.Println("error: in IP4 stop:", err)
	}
	if err := h.HandlerIP6.Stop(); err != nil {
		fmt.Println("error: in IP6 stop:", err)
	}
	if err := h.HandlerICMP4.Stop(); err != nil {
		fmt.Println("error: in ICMP4 stop:", err)
	}
	if err := h.HandlerICMP6.Stop(); err != nil {
		fmt.Println("error: in ICMP6 stop:", err)
	}
	if err := h.HandlerARP.Stop(); err != nil {
		fmt.Println("error: in ARP stop:", err)
	}
	if err := h.HandlerDHCP4.Stop(); err != nil {
		fmt.Println("error: in DHCP4 stop:", err)
	}
	return nil
}

// ListenAndServe listen for raw packets and invoke hooks as required
func (h *Handler) ListenAndServe(ctxt context.Context) (err error) {

	// start all plugins
	go h.startPlugins()
	defer h.stopPlugins()

	go h.purgeLoop(ctxt, h.OfflineDeadline, h.PurgeDeadline)

	buf := make([]byte, EthMaxSize)
	for {
		if err = h.conn.SetReadDeadline(time.Now().Add(time.Second * 2)); err != nil {
			if h.closed { // closed by call to h.Close()?
				return nil
			}
			return fmt.Errorf("setReadDeadline error: %w", err)
		}

		n, _, err := h.conn.ReadFrom(buf)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			if h.closed { // closed by call to h.Close()?
				return nil
			}
			return fmt.Errorf("read error: %w", err)
		}

		ether := Ether(buf[:n])
		if !ether.IsValid() {
			log.Error("icmp invalid ethernet packet ", ether.EtherType())
			continue
		}

		// Ignore packets sent via our interface
		// If we don't have this, then we received all forward packets with client IPs but our mac
		//
		// TODO: should this be in the bpf rules?
		if bytes.Equal(ether.Src(), h.NICInfo.HostMAC) {
			continue
		}
		// fmt.Println("DEBUG ether ", ether)

		// Only interested in unicast ethernet
		if !isUnicastMAC(ether.Src()) {
			continue
		}

		var ip4Frame IP4
		var ip6Frame IP6
		var l4Proto int
		var l4Payload []byte
		var host *Host
		switch ether.EtherType() {
		case syscall.ETH_P_IP:
			ip4Frame = IP4(ether.Payload())
			if !ip4Frame.IsValid() {
				fmt.Println("packet: error invalid ip4 frame type=", ether.EtherType())
				continue
			}
			if DebugIP4 {
				fmt.Println("ether:", ether)
				fmt.Println("ip4  :", ip4Frame)
			}

			// Only lookup host on same subnet
			if h.NICInfo.HostIP4.Contains(ip4Frame.Src()) {
				host, _ = h.LANHosts.FindOrCreateHost(ether.Src(), ip4Frame.Src())
			}
			l4Proto = ip4Frame.Protocol()
			l4Payload = ip4Frame.Payload()
			// h.handlerIP4.ProcessPacket(host, ether)

		case syscall.ETH_P_IPV6:
			ip6Frame = IP6(ether.Payload())
			if !ip6Frame.IsValid() {
				fmt.Println("packet: error invalid ip6 frame type=", ether.EtherType())
				continue
			}
			if DebugIP6 {
				fmt.Printf("ether: %s\n", ether)
				fmt.Printf("ip6  : %s\n", ip6Frame)
			}

			l4Proto = ip6Frame.NextHeader()
			l4Payload = ip6Frame.Payload()

			// lookup host only if unicast
			if ip6Frame.Src().IsLinkLocalUnicast() || ip6Frame.Src().IsGlobalUnicast() {
				host, _ = h.LANHosts.FindOrCreateHost(ether.Src(), ip6Frame.Src())
			}
			// h.handlerIP6.ProcessPacket(host, ether)

		case syscall.ETH_P_ARP:
			if host, err = h.HandlerARP.ProcessPacket(host, ether); err != nil {
				fmt.Printf("packet: error processing arp: %s\n", err)
			}
			l4Proto = 0 // skip next check

		default:
			fmt.Printf("packet: error invalid ethernet type=%x\n", ether.EtherType())
			continue
		}

		switch l4Proto {
		case syscall.IPPROTO_ICMP:
			if host, err = h.HandlerICMP4.ProcessPacket(host, l4Payload); err != nil {
				fmt.Printf("packet: error processing icmp4: %s\n", err)
			}
		case syscall.IPPROTO_ICMPV6:
			if host, err = h.HandlerICMP6.ProcessPacket(host, ether); err != nil {
				fmt.Printf("packet: error processing icmp6: %s\n", err)
			}
		case syscall.IPPROTO_IGMP:
			// Internet Group Management Protocol - Ipv4 multicast groups
			// do nothing
		case syscall.IPPROTO_TCP:
			// skip tcp
		case syscall.IPPROTO_UDP:
			udp := UDP(l4Payload)
			if !udp.IsValid() {
				fmt.Println("packet: error invalid udp frame ", ip4Frame)
				continue
			}
			if ip4Frame != nil {
				if DebugUDP {
					fmt.Println("ether:", ether)
					fmt.Println("ip4  :", ip4Frame)
					fmt.Printf("udp  : %s\n", udp)
				}
				if udp.DstPort() == DHCP4ServerPort {
					if host, err = h.HandlerDHCP4.ProcessPacket(host, ether); err != nil {
						fmt.Printf("packet: error processing dhcp4: %s\n", err)
					}
				}
			} else {
				if DebugUDP {
					fmt.Println("ether:", ether)
					fmt.Println("ip6  :", ip6Frame)
					fmt.Printf("udp  : %s\n", udp)
				}

			}

		case 0: // skip ARP

		default:
			fmt.Println("packet: unsupported level 4 header", l4Proto)
		}

		// Lock and sset to online
		h.LANHosts.Lock()
		if host != nil && !host.Online {
			host.Online = true // make sure we don't have a lock
			mac := host.MAC
			ip := host.IP
			h.LANHosts.Unlock()
			h.makeOnline(mac, ip)
		} else {
			h.LANHosts.Unlock()
		}
	}
}

func (h *Handler) makeOnline(mac net.HardwareAddr, ip net.IP) {
	if Debug {
		fmt.Printf("packet: IP is online ip=%s mac=%s\n", ip, mac)
	}
	if h.captureList.Index(mac) != -1 {
		h.startHuntHandlers(mac)
	}
	notification := Notification{IP: ip, MAC: mac, Online: true}
	go h.notifyCallback(notification)
}

func (h *Handler) makeOffline(mac net.HardwareAddr, ip net.IP) {
	if Debug {
		fmt.Printf("packet: IP is offline ip=%s mac=%s\n", ip, mac)
	}
	if h.captureList.Index(mac) != -1 {
		h.stopHuntHandlers(mac)
	}
	notification := Notification{IP: ip, MAC: mac, Online: false}
	go h.notifyCallback(notification)
}
