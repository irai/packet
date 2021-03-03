package arp

import (
	"fmt"
	"net"
	"sync"

	"log"

	"github.com/irai/packet"
)

type Data struct {
	IPArray [nIPs]IPEntry
	State   arpState
	ClaimIP bool // if true, will claim the target IP; likely to force the target IP to stop working
}

// must implement interface
var _ packet.PacketProcessor = &Handler{}

// Handler stores instance variables
type Handler struct {
	virtual      *arpTable
	notification chan<- MACEntry // notification channel for state change
	wg           sync.WaitGroup
	arpMutex     sync.RWMutex
	engine       *packet.Handler
}

var (
	// Debug - set Debug to true to see debugging messages
	Debug bool
)

// Open creates the ARP handler and attach to the engine
func Open(engine *packet.Handler) (h *Handler, err error) {
	h = &Handler{engine: engine}
	// h.table, _ = loadARPProcTable() // load linux proc table
	h.virtual = newARPTable()
	if h.engine.NICInfo.HostIP4.IP.To4() == nil {
		return nil, packet.ErrInvalidIP4
	}

	if h.engine.NICInfo.HomeLAN4.IP.To4() == nil || h.engine.NICInfo.HomeLAN4.IP.IsUnspecified() {
		return nil, packet.ErrInvalidIP4
	}
	h.engine.HandlerARP = h

	return h, nil
}

// Close removes the plugin from the engine
func (h *Handler) Close() error {
	h.engine.HandlerARP = packet.PacketNOOP{}
	return nil
}

// StartHunt implements PacketProcessor interface
func (h *Handler) StartHunt(mac net.HardwareAddr) error {
	return h.startSpoof(mac)
}

// StopHunt implements PacketProcessor interface
func (h *Handler) StopHunt(mac net.HardwareAddr) error {
	return h.stopSpoof(mac)
}

// Stop implements PacketProcessor interface
func (h *Handler) Stop() error {
	return nil
}

// PrintTable print the ARP table to stdout.
func (h *Handler) PrintTable() {
	h.virtual.printTable()
}

// Close will terminate the ListenAndServer goroutine as well as all other pending goroutines.
func (h *Handler) End() {
	// Don't close the socket - it is shared with packet
}

// Start start background processes
func (h *Handler) Start() error {
	return nil
}

const (
	request = iota
	reply
	announcement
	gratuitous
	probe
)

// ProcessPacket handles an incoming ARP packet
//
// Virtual MACs
// A virtual MAC is a fake mac address used when claiming an existing IP during spoofing.
// ListenAndServe will send ARP reply on behalf of virtual MACs
//
// ARP: packet types
//      note that RFC 3927 specifies 00:00:00:00:00:00 for Request TargetMAC
// +============+===+===========+===========+============+============+===================+===========+
// | Type       | op| EthDstMAC | EthSRCMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
// +============+===+===========+===========+============+============+===================+===========+
// | request    | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  targetIP |
// | reply      | 2 | clientMAC | targetMAC | targetMAC  | targetIP   | clientMAC         |  clientIP |
// | gratuitous | 2 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
// +============+===+===========+===========+============+============+===================+===========+
func (h *Handler) ProcessPacket(host *packet.Host, b []byte) (*packet.Host, error) {

	ether := packet.Ether(b)
	frame := ARP(ether.Payload())
	if !frame.IsValid() {
		return host, packet.ErrParseMessage
	}

	// skip link local packets
	if frame.SrcIP().IsLinkLocalUnicast() || frame.DstIP().IsLinkLocalUnicast() {
		if Debug {
			log.Printf("arp skipping link local packet smac=%v sip=%v tmac=%v tip=%v", frame.SrcMAC(), frame.SrcIP(), frame.DstMAC(), frame.DstIP())
		}
		return host, nil
	}

	var operation int
	switch {
	case frame.Operation() == OperationReply:
		operation = reply
	case frame.Operation() == OperationRequest:
		switch {
		case frame.SrcIP().Equal(frame.DstIP()):
			operation = announcement
		case frame.SrcIP().Equal(net.IPv4zero):
			operation = probe
		default:
			operation = request
		}
	default:
		log.Printf("arp invalid operation: %s", frame)
		return host, nil
	}

	switch operation {
	case request:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| EthDstMAC | EthSRCMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | request    | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  targetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fmt.Println("ether:", ether)
			fmt.Printf("arp  : who is %s: %s\n", frame.DstIP(), frame)
		}
		// if targetIP is a virtual host, we are claiming the ip; reply and return
		h.arpMutex.RLock()
		if target := h.virtual.findVirtualIP(frame.DstIP()); target != nil {
			mac := target.MAC
			h.arpMutex.RUnlock()
			if Debug {
				log.Printf("arp ip=%s is virtual - send reply smac=%v", frame.DstIP(), mac)
			}
			h.reply(frame.SrcMAC(), mac, frame.DstIP(), EthernetBroadcast, frame.DstIP())
			return host, nil
		}
		h.arpMutex.RUnlock()

	case probe:
		// We are not interested in probe ACD (Address Conflict Detection) packets
		// if this is a probe, the sender IP will be zeros; do nothing as the sender IP is not valid yet.
		//
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fmt.Println("ether:", ether)
			fmt.Printf("arp  : probe recvd: %s\n", frame)
		}

		// don't continue
		return host, nil

	case announcement:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fmt.Println("ether:", ether)
			fmt.Printf("arp  : announcement recvd: %s\n", frame)
		}
		// if targetIP is a virtual host, we are claiming the ip; reply and return
		h.arpMutex.RLock()
		if target := h.virtual.findVirtualIP(frame.DstIP()); target != nil {
			mac := target.MAC
			h.arpMutex.RUnlock()
			if Debug {
				log.Printf("arp ip=%s is virtual - send reply smac=%v", frame.DstIP(), mac)
			}
			h.reply(frame.SrcMAC(), mac, frame.DstIP(), EthernetBroadcast, frame.DstIP())
			return host, nil
		}
		h.arpMutex.RUnlock()

	default:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| EthDstMAC | EthSRCMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | reply      | 2 | clientMAC | targetMAC | targetMAC  | targetIP   | clientMAC         |  clientIP |
		// | gratuitous | 2 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fmt.Println("ether:", ether)
			fmt.Printf("arp  : reply recvd: %s\n", frame)
		}
	}

	// If new client, then create a MACEntry in table
	if host == nil && h.engine.NICInfo.HostIP4.Contains(frame.SrcIP()) {
		host, _ = h.engine.LANHosts.FindOrCreateHost(frame.SrcMAC(), frame.SrcIP())
	}
	return host, nil
}
