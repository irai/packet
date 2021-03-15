package arp

import (
	"fmt"
	"net"
	"sync"
	"time"

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

// MinuteTicker implements packet processor interface
//
// ARP handler will send who is packet if IP has not been seen
func (h *Handler) MinuteTicker(now time.Time) error {
	arpAddrs := []packet.Addr{}
	now.Add(h.engine.ProbeInterval * -1) //

	h.engine.Lock()
	for _, host := range h.engine.LANHosts.Table {
		if host.Online && host.LastSeen.Before(now) && host.IP.To4() != nil {
			arpAddrs = append(arpAddrs, packet.Addr{MAC: host.MACEntry.MAC, IP: host.IP})
		}
	}
	h.engine.Unlock()

	for _, addr := range arpAddrs {
		h.Request(h.engine.NICInfo.HostMAC, h.engine.NICInfo.HostIP4.IP, addr.MAC, addr.IP.To4())
	}
	return nil
}

// HuntStage implemente PacketProcessor interface
func (h *Handler) HuntStage(addr packet.Addr) packet.HuntStage { return packet.StageNormal }

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
		h.engine.Lock()
		if host != nil && host.HuntStageNoLock() == packet.StageHunt && frame.DstIP().Equal(h.engine.NICInfo.RouterIP4.IP) {
			h.engine.Unlock()
			if Debug {
				log.Printf("arp: router spoofing - send reply i am ip=%s", frame.DstIP())
			}
			h.reply(frame.SrcMAC(), h.engine.NICInfo.HostMAC, frame.DstIP(), frame.SrcMAC(), frame.SrcIP())
			return host, nil
		}
		h.engine.Unlock()

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

		// reject any other ip
		h.engine.Lock()
		macEntry := h.engine.FindMACEntryNoLock(frame.SrcMAC())
		if macEntry == nil || !macEntry.IP4Offer.Equal(frame.DstIP()) {
			h.engine.Unlock()
			// fmt.Printf("DEBUG arp  : probe reject for ip=%s from mac=%s\n", frame.DstIP(), frame.SrcMAC())

			// If probing for lan IP, then unicast reply to srcMAC
			//
			// Note: detected one situation where android probed external DNS IP. Not sure if this occur in other clients.
			//     arp  : probe reject for ip=8.8.8.8 from mac=84:11:9e:03:89:c0 (android phone) - 10 March 2021
			if h.engine.NICInfo.HomeLAN4.Contains(frame.DstIP()) {
				fmt.Printf("arp  : probe reject for ip=%s from mac=%s\n", frame.DstIP(), frame.SrcMAC())
				h.reply(frame.SrcMAC(), h.engine.NICInfo.HostMAC, frame.DstIP(), frame.SrcMAC(), net.IP(EthernetBroadcast))
			}
			return host, nil
		}
		h.engine.Unlock()

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
