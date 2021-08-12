package arp

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

type ARPHandler interface {
	packet.PacketProcessor
}

// must implement interface
var _ ARPHandler = &Handler{}

// Handler stores instance variables
type Handler struct {
	arpMutex      sync.RWMutex
	session       *packet.Session
	probeInterval time.Duration // how often to probe if IP is online
	huntList      map[string]packet.Addr
	closed        bool
	closeChan     chan bool
}

type Config struct {
	ProbeInterval time.Duration
}

var (
	// Debug - set Debug to true to see debugging messages
	Debug bool
)

const module = "arp"

// New creates the ARP handler and attach to the engine
func New(session *packet.Session) (h *Handler, err error) {
	return Config{ProbeInterval: time.Minute * 5}.New(session)
}

func (config Config) New(session *packet.Session) (h *Handler, err error) {
	h = &Handler{session: session, huntList: make(map[string]packet.Addr, 6), closeChan: make(chan bool)}
	if h.session.NICInfo.HostIP4.IP.To4() == nil {
		return nil, packet.ErrInvalidIP
	}

	if h.session.NICInfo.HomeLAN4.IP.To4() == nil || h.session.NICInfo.HomeLAN4.IP.IsUnspecified() {
		return nil, packet.ErrInvalidIP
	}
	h.probeInterval = config.ProbeInterval

	return h, nil
}

// Detach removes the plugin from the engine
func (h *Handler) Close() error {
	h.closed = true
	close(h.closeChan) // this will exit all background goroutines
	return nil
}

// Stop implements PacketProcessor interface
func (h *Handler) Stop() error {
	return nil
}

// PrintTable print the ARP table to stdout.
func (h *Handler) PrintTable() {
	h.arpMutex.Lock()
	defer h.arpMutex.Unlock()
	for _, v := range h.huntList {
		fastlog.NewLine(module, "hunting").Struct(v).Write()
		// fmt.Printf("arp   : hunting %s", v)
	}
}

// End will terminate the ListenAndServer goroutine as well as all other pending goroutines.
func (h *Handler) End() {
	// Don't close the socket - it is shared with packet
}

// Start background processes
func (h *Handler) Start() error {
	return h.ScanNetwork(context.Background(), h.session.NICInfo.HostIP4)
}

// MinuteTicker implements packet processor interface
//
// ARP handler will send who is packet if IP has not been seen
func (h *Handler) MinuteTicker(now time.Time) error {
	arpAddrs := []packet.Addr{}
	now.Add(h.probeInterval * -1) //

	for _, host := range h.session.GetHosts() {
		host.MACEntry.Row.RLock()
		if host.Online && host.LastSeen.Before(now) && host.Addr.IP.To4() != nil {
			arpAddrs = append(arpAddrs, host.Addr)
		}
		host.MACEntry.Row.RUnlock()
	}

	for _, addr := range arpAddrs {
		if err := h.RequestTo(addr.MAC, addr.IP); err != nil {
			return err
		}
	}
	return nil
}

// CheckAddr implements the PacketProcessor interface
//
// The ARP handler sends a ARP Request packet
func (h *Handler) CheckAddr(addr packet.Addr) (packet.HuntStage, error) {
	err := h.Request(addr.IP)
	h.arpMutex.Lock()
	defer h.arpMutex.Unlock()
	if _, found := h.huntList[string(addr.MAC)]; found {
		return packet.StageHunt, err
	}
	return packet.StageNormal, err
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
func (h *Handler) ProcessPacket(host *packet.Host, b []byte, header []byte) (packet.Result, error) {

	ether := packet.Ether(b)
	frame := ARP(header)
	if !frame.IsValid() {
		return packet.Result{}, packet.ErrParseFrame
	}

	// skip link local packets
	if frame.SrcIP().IsLinkLocalUnicast() || frame.DstIP().IsLinkLocalUnicast() {
		if Debug {
			fastlog.NewLine(module, "skipping link local packet").Struct(frame).Write()
		}
		return packet.Result{}, nil
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
		fastlog.NewLine(module, "invalid operation").Struct(frame).Write()
		// fmt.Printf("arp   : invalid operation: %s\n", frame)
		return packet.Result{}, nil
	}

	switch operation {
	case request:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| EthDstMAC | EthSRCMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | request    | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  targetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fastlog.NewLine(module, "ether").Struct(ether).Module(module, "who is").IP("ip", frame.DstIP()).Struct(frame).Write()
		}
		// if we are spoofing the src host and the src host is trying to discover the router IP,
		// reply on behalf of the router
		h.arpMutex.Lock()
		_, hunting := h.huntList[string(frame.SrcMAC())]
		h.arpMutex.Unlock()
		if hunting && frame.DstIP().Equal(h.session.NICInfo.RouterIP4.IP) {
			if Debug {
				fastlog.NewLine(module, "router spoofing - send reply i am").IP("ip", frame.DstIP()).Write()
				// fmt.Printf("arp   : router spoofing - send reply i am ip=%s\n", frame.DstIP())
			}
			h.reply(frame.SrcMAC(), packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: frame.DstIP()}, packet.Addr{MAC: frame.SrcMAC(), IP: frame.SrcIP()})
			return packet.Result{}, nil
		}

	case probe:
		// We are interested in probe ACD (Address Conflict Detection) packets for IPs that we have an open DHCP offer
		// if this is a probe, the sender IP will be zeros; send ARP reply to stop sender from acquiring the IP
		// but don't create host entry - the host has not claimed the IP yet
		//
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fastlog.NewLine(module, "ether").Struct(ether).Module(module, "probe recvd").Struct(frame).Write()
		}

		// reject any other ip
		// TODO: need to lock MACEntry?
		macEntry := h.session.FindMACEntry(frame.SrcMAC())
		if macEntry == nil || !macEntry.IP4Offer.Equal(frame.DstIP()) {
			// fmt.Printf("DEBUG arp  : probe reject for ip=%s from mac=%s\n", frame.DstIP(), frame.SrcMAC())

			// If probing for lan IP, then unicast reply to srcMAC
			//
			// Note: detected one situation where android probed external DNS IP. Not sure if this occur in other clients.
			//     arp  : probe reject for ip=8.8.8.8 from mac=84:11:9e:03:89:c0 (android phone) - 10 March 2021
			if h.session.NICInfo.HomeLAN4.Contains(frame.DstIP()) {
				fastlog.NewLine(module, "probe reject for").IP("ip", frame.DstIP()).MAC("fromMAC", frame.SrcMAC()).Struct(macEntry).Write()
				// fmt.Printf("arp   : probe reject for ip=%s from mac=%s macentry=%s\n", frame.DstIP(), frame.SrcMAC(), macEntry)
				h.reply(frame.SrcMAC(), packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: frame.DstIP()}, packet.Addr{MAC: frame.SrcMAC(), IP: net.IP(EthernetBroadcast)})
			}
		}
		return packet.Result{}, nil

	case announcement:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fastlog.NewLine(module, "ether").Struct(ether).Module(module, "announcement recvd").Struct(frame).Write()
			// fmt.Println("ether :", ether)
			// fmt.Printf("arp   : announcement recvd: %s\n", frame)
		}

	default:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| EthDstMAC | EthSRCMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | reply      | 2 | clientMAC | targetMAC | targetMAC  | targetIP   | clientMAC         |  clientIP |
		// | gratuitous | 2 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Debug {
			fastlog.NewLine(module, "ether").Struct(ether).Module(module, "reply recvd").Struct(frame).Write()
			// fmt.Println("ether :", ether)
			// fmt.Printf("arp   : reply recvd: %s\n", frame)
		}
	}

	if host == nil && h.session.NICInfo.HostIP4.Contains(frame.SrcIP()) {
		return packet.Result{Update: true, FrameAddr: packet.Addr{MAC: frame.SrcMAC(), IP: frame.SrcIP()}}, nil
	}
	return packet.Result{}, nil
}
