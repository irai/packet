package packet

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/irai/packet/raw"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"
)

// Debug packets turn on logging if desirable
var (
	Debug    bool
	DebugIP6 bool
	DebugIP4 bool
)

// Config has a list of configurable parameters that overide package defaults
type Config struct {

	// Conn enables the client to override the connection with a another packet conn
	// usefule for testing
	Conn    net.PacketConn // listen connectinon
	NICInfo *raw.NICInfo   // override nic information
}

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler struct {
	NICInfo      *raw.NICInfo
	conn         net.PacketConn
	LANHosts     *raw.HostTable
	HandlerIP4   raw.PacketProcessor
	HandlerIP6   raw.PacketProcessor
	HandlerICMP4 raw.PacketProcessor
	HandlerICMP6 raw.PacketProcessor
	HandlerARP   raw.PacketProcessor
	callback     []func(Notification) error
	captureList  []net.HardwareAddr
	sync.Mutex
}

// ppNOOP is a no op packet processor
type ppNOOP struct{}

var _ raw.PacketProcessor = ppNOOP{}

func (p ppNOOP) Start() error                                       { return nil }
func (p ppNOOP) Stop() error                                        { return nil }
func (p ppNOOP) ProcessPacket(*raw.Host, []byte) (*raw.Host, error) { return nil, nil }
func (p ppNOOP) StartHunt(net.HardwareAddr) error                   { return nil }
func (p ppNOOP) StopHunt(net.HardwareAddr) error                    { return nil }

// New creates an ICMPv6 handler with default values
func New(nic string) (*Handler, error) {
	return Config{}.New(nic)
}

// New creates an packet handler with config values
func (config Config) New(nic string) (*Handler, error) {

	var err error

	h := &Handler{LANHosts: raw.New()}

	h.NICInfo = config.NICInfo
	if h.NICInfo == nil {
		h.NICInfo, err = raw.GetNICInfo(nic)
		if err != nil {
			return nil, fmt.Errorf("interface not found nic=%s: %w", nic, err)
		}
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
	h.HandlerARP = ppNOOP{}
	h.HandlerIP4 = ppNOOP{}
	h.HandlerIP6 = ppNOOP{}
	h.HandlerARP = ppNOOP{}
	h.HandlerICMP4 = ppNOOP{}
	h.HandlerICMP6 = ppNOOP{}

	return h, nil
}

// Close closes the underlying sockets
func (h *Handler) Close() error {
	fmt.Println("DEBUG closing server")
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
		bpf.RetConstant{Val: raw.EthMaxSize},
		// IPv6?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_IPV6, SkipFalse: 1},
		bpf.RetConstant{Val: raw.EthMaxSize},
		// ARP?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_ARP, SkipFalse: 1},
		bpf.RetConstant{Val: raw.EthMaxSize},
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		log.Fatal("bpf assemble error", err)
	}

	// see: https://www.man7.org/linux/man-pages/man7/packet.7.html
	conn, err = raw.NewServerConn(h.NICInfo.IFI, syscall.ETH_P_ALL, raw.Config{Filter: bpf})
	if err != nil {
		return nil, fmt.Errorf("raw.ListenPacket error: %w", err)
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

func (h *Handler) start() error {
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
	return nil
}

func (h *Handler) end() error {
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
	return nil
}

// ListenAndServe listen for raw packets and invoke hooks as required
func (h *Handler) ListenAndServe(ctxt context.Context) (err error) {

	// start all plugins
	go h.start()
	defer h.end()

	// Offline in 5 minutes, purge in 30
	go h.purgeLoop(ctxt, time.Minute*5, time.Minute*30)

	buf := make([]byte, raw.EthMaxSize)
	for {
		if err = h.conn.SetReadDeadline(time.Now().Add(time.Second * 2)); err != nil {
			if ctxt.Err() != context.Canceled {
				return fmt.Errorf("setReadDeadline error: %w", err)
			}
			return
		}

		n, _, err := h.conn.ReadFrom(buf)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			if ctxt.Err() != context.Canceled {
				return fmt.Errorf("read error: %w", err)
			}
			return nil
		}

		ether := raw.Ether(buf[:n])
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

		// Only interested in unicast ethernet
		if !isUnicastMAC(ether.Src()) {
			continue
		}

		var l4Proto int
		var l4Payload []byte
		var host *raw.Host
		switch ether.EtherType() {
		case syscall.ETH_P_IP:
			frame := raw.IP4(ether.Payload())
			if !frame.IsValid() {
				fmt.Println("packet: error invalid ip4 frame type=", ether.EtherType())
				continue
			}
			if DebugIP4 {
				fmt.Println("ether:", ether)
				fmt.Println("ip4  :", frame)
			}
			if !h.NICInfo.HostIP4.Contains(frame.Src()) { // must be on the same net
				// if !frame.Src().IsLinkLocalUnicast() && !frame.Src().IsGlobalUnicast() {
				// fmt.Println("ignore IP4 ", frame)
				continue
			}
			host, _ = h.LANHosts.FindOrCreateHost(ether.Src(), frame.Src())
			l4Proto = frame.Protocol()
			l4Payload = frame.Payload()
			// h.handlerIP4.ProcessPacket(host, ether)

		case syscall.ETH_P_IPV6:
			frame := raw.IP6(ether.Payload())
			if !frame.IsValid() {
				fmt.Println("packet: error invalid ip6 frame type=", ether.EtherType())
				continue
			}
			if DebugIP6 {
				fmt.Println("ether:", ether)
				fmt.Printf("ip6  : %s\n", frame)
			}

			l4Proto = frame.NextHeader()
			l4Payload = frame.Payload()

			// lookup host only if unicast
			if frame.Src().IsLinkLocalUnicast() || frame.Src().IsGlobalUnicast() {
				host, _ = h.LANHosts.FindOrCreateHost(ether.Src(), frame.Src())
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
		case syscall.IPPROTO_TCP, syscall.IPPROTO_UDP:
			// do nothing

		case 0: // skip ARP

		default:
			fmt.Println("packet: unsupported level 4 header", l4Proto)
		}

		// Set to online
		if host != nil && !host.Online {
			host.SetOnline()
			h.notifyCallback(host)
		}
	}
}
