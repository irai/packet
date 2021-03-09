package arp

import (
	"fmt"
	"net"
	"sync"

	"log"

	"github.com/irai/packet"
)

// must implement interface
var _ packet.PacketProcessor = &Handler{}

// Handler stores instance variables
type Handler struct {
	arpMutex  sync.RWMutex
	engine    *packet.Handler
	closed    bool
	closeChan chan bool
}

var (
	// Debug - set Debug to true to see debugging messages
	Debug bool
)

// Attach creates the ARP handler and attach to the engine
func Attach(engine *packet.Handler) (h *Handler, err error) {
	h = &Handler{engine: engine, closeChan: make(chan bool)}
	// h.table, _ = loadARPProcTable() // load linux proc table
	if h.engine.NICInfo.HostIP4.IP.To4() == nil {
		return nil, packet.ErrInvalidIP
	}

	if h.engine.NICInfo.HomeLAN4.IP.To4() == nil || h.engine.NICInfo.HomeLAN4.IP.IsUnspecified() {
		return nil, packet.ErrInvalidIP
	}
	h.engine.HandlerARP = h

	return h, nil
}

// Detach removes the plugin from the engine
func (h *Handler) Detach() error {
	h.closed = true
	close(h.closeChan) // this will exit all background goroutines
	h.engine.HandlerARP = packet.PacketNOOP{}
	return nil
}

// Stop implements PacketProcessor interface
func (h *Handler) Stop() error {
	return nil
}

// PrintTable print the ARP table to stdout.
func (h *Handler) PrintTable() {
	return // nothing to do
	// h.engine.PrintTable()
}

// End will terminate the ListenAndServer goroutine as well as all other pending goroutines.
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
// | request    | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  targetIP |  - ff target mac
// | request    | 1 | broadcast | clientMAC | clientMAC  | clientIP   | 00:00:00:00:00:00 |  targetIP |  - 00 target mac
// | reply      | 2 | clientMAC | targetMAC | targetMAC  | targetIP   | clientMAC         |  clientIP |
// | gratuitous | 2 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 00:00:00:00:00:00 |  targetIP |
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
		// if we are spoofing the IP, reply on behals of host
		if host != nil && host.HuntStageIP4 == packet.StageHunt && frame.DstIP().Equal(h.engine.NICInfo.RouterIP4.IP) {
			if Debug {
				log.Printf("arp: router spoofing - send reply i am ip=%s", frame.DstIP())
			}
			h.reply(frame.SrcMAC(), h.engine.NICInfo.HostMAC, frame.DstIP(), frame.SrcMAC(), frame.SrcIP())
			return host, nil
		}

	case probe:
		// We are interested in probe ACD (Address Conflict Detection) packets for IPs that we have an open DHCP offer
		// if this is a probe, the sender IP will be zeros; send ARP reply to stop sender from acquiring the IP
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
		// if there is an open DHCP offer, then reject any other ip
		// if ip := h.engine.CaptureList.GetIP4(frame.SrcMAC()); ip != nil && !ip.Equal(frame.DstIP()) {
		if ip := h.engine.MACTableGetIP4(frame.SrcMAC()); ip != nil && !ip.Equal(frame.DstIP()) {
			// if Debug {
			fmt.Printf("arp  : probe reject for ip=%s from mac=%s\n", frame.DstIP(), frame.SrcMAC())
			// }
			// Unicast reply
			h.reply(frame.SrcMAC(), h.engine.NICInfo.HostMAC, frame.DstIP(), frame.SrcMAC(), net.IP(EthernetBroadcast))
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
		/***
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
		***/

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
		host, _ = h.engine.FindOrCreateHost(frame.SrcMAC(), frame.SrcIP())
	}
	return host, nil
}
