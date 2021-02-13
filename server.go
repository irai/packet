package packet

import (
	"context"
	"errors"
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
var Debug bool

// Sentinel errors
var (
	ErrParseMessage = errors.New("failed to parse message")
)

type Hook struct {
	name     string
	function func(*Host, []byte) error
}

// Config has a list of configurable parameters that overide package defaults
type Config struct {
	// Conn enables the client to override the connection with a another packet conn
	// usefule for testing
	Conn net.PacketConn
}

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler struct {
	conn         net.PacketConn
	mutex        sync.Mutex
	ifi          *net.Interface
	LANHosts     map[string]*Host
	Config       Config
	handlerIP4   []Hook
	handlerIP6   []Hook
	handlerICMP4 []Hook
	handlerICMP6 []Hook
	handlerARP   Hook
}

func (h *Handler) IP4Hook(name string, f func(*Host, []byte) error) error {
	hook := Hook{name: name, function: f}
	h.handlerIP4 = append(h.handlerIP4, hook)
	return nil
}

func (h *Handler) IP6Hook(name string, f func(*Host, []byte) error) error {
	hook := Hook{name: name, function: f}
	h.handlerIP6 = append(h.handlerIP6, hook)
	return nil
}
func (h *Handler) ARPHook(name string, f func(*Host, []byte) error) error {
	h.handlerARP = Hook{name: name, function: f}
	return nil
}
func (h *Handler) ICMP4Hook(name string, f func(*Host, []byte) error) error {
	hook := Hook{name: name, function: f}
	h.handlerICMP4 = append(h.handlerICMP4, hook)
	return nil
}
func (h *Handler) ICMP6Hook(name string, f func(*Host, []byte) error) error {
	hook := Hook{name: name, function: f}
	h.handlerICMP6 = append(h.handlerICMP6, hook)
	return nil
}

// New creates an ICMPv6 handler with default values
func New(nic string) (*Handler, error) {
	return Config{}.New(nic)
}

// New creates an ICMPv6 handler with config values
func (config Config) New(nic string) (*Handler, error) {
	var err error

	h := &Handler{Config: config, LANHosts: make(map[string]*Host, 64)}

	// Override conn
	if config.Conn != nil {
		h.conn = config.Conn
		return h, nil
	}

	h.ifi, err = net.InterfaceByName(nic)
	if err != nil {
		return nil, fmt.Errorf("interface not found nic=%s: %w", nic, err)
	}

	// see syscall constants for full list of available network protocols
	// https://golang.org/pkg/syscall/
	bpf, err := bpf.Assemble([]bpf.Instruction{
		// Check EtherType
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 80221Q?
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
	h.conn, err = raw.ListenPacket(h.ifi, syscall.ETH_P_ALL, raw.Config{Filter: bpf})
	if err != nil {
		return nil, fmt.Errorf("raw.ListenPacket error: %w", err)
	}

	return h, nil
}

// Close closes the underlying sockets
func (h *Handler) Close() error {
	h.conn.Close()
	return nil
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

// ListenAndServe listen for raw packets and invoke hooks as required
func (h *Handler) ListenAndServe(ctxt context.Context) (err error) {

	buf := make([]byte, raw.EthMaxSize)
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
		if !ether.IsValid() {
			log.Error("icmp invalid ethernet packet ", ether.EtherType())
			continue
		}
		if !isUnicastMAC(ether.Src()) {
			continue
		}
		if Debug {
			fmt.Println("ether: ", ether)
		}

		var l4Proto int
		var l4Payload []byte
		var host *Host
		switch ether.EtherType() {
		case syscall.ETH_P_IP:
			frame := raw.IP4(ether.Payload())
			if !frame.IsValid() {
				fmt.Println("icmp: error invalid ip4 frame type=", ether.EtherType())
				continue
			}
			if Debug {
				fmt.Println("ip4  : ", frame)
			}
			if !frame.Src().IsLinkLocalUnicast() && !frame.Src().IsGlobalUnicast() {
				fmt.Println("ignore IP4 ", frame)
				continue
			}
			host, _ = h.findOrCreateHost(ether.Src(), frame.Src())
			l4Proto = frame.Protocol()
			l4Payload = frame.Payload()
			for _, v := range h.handlerIP4 {
				v.function(host, ether)
			}

		case syscall.ETH_P_IPV6:
			frame := raw.IP6(ether.Payload())
			if !frame.IsValid() {
				fmt.Println("icmp: error invalid ip6 frame type=", ether.EtherType())
				continue
			}
			if Debug {
				fmt.Println("ip6  : ", frame)
			}

			if !frame.Src().IsLinkLocalUnicast() && !frame.Src().IsGlobalUnicast() {
				fmt.Println("ignore IP6 ", frame)
				continue
			}
			l4Proto = frame.NextHeader()
			l4Payload = frame.Payload()

			host, _ = h.findOrCreateHost(ether.Src(), frame.Src())
			for _, v := range h.handlerIP6 {
				v.function(host, ether)
			}

		case syscall.ETH_P_ARP:
			if err := h.handlerARP.function(host, ether.Payload()); err != nil {
				fmt.Printf("packet: error processing arp: %s\n", err)
			}
			continue // Skip nextHeader check

		default:
			fmt.Printf("packet: error invalid ethernet type=%x\n", ether.EtherType())
			continue
		}

		switch l4Proto {
		case syscall.IPPROTO_ICMP:
			for _, v := range h.handlerICMP4 {
				v.function(host, l4Payload)
			}
		case syscall.IPPROTO_ICMPV6:
			for _, v := range h.handlerICMP6 {
				v.function(host, l4Payload)
			}
		case syscall.IPPROTO_TCP, syscall.IPPROTO_UDP:
			// do nothing

		default:
			fmt.Println("unsupported level 4 header", l4Proto)
		}
	}
}
