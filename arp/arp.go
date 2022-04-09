package arp

import (
	"sync"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

const (
	request = iota
	reply
	announcement
	gratuitous
	probe
)

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

const module = "arp"

var Logger = fastlog.New(module)

// New creates the ARP handler
func New(session *packet.Session) (h *Handler, err error) {
	return Config{ProbeInterval: time.Minute * 5}.New(session)
}

func (config Config) New(session *packet.Session) (h *Handler, err error) {
	h = &Handler{session: session, huntList: make(map[string]packet.Addr, 6), closeChan: make(chan bool)}
	if !h.session.NICInfo.HostAddr4.IP.Is4() {
		return nil, packet.ErrInvalidIP
	}

	if !h.session.NICInfo.HomeLAN4.Addr().Is4() || h.session.NICInfo.HomeLAN4.Addr().IsUnspecified() {
		return nil, packet.ErrInvalidIP
	}
	h.probeInterval = config.ProbeInterval

	return h, nil
}

// Close the handler and terminate all internal goroutines
func (h *Handler) Close() error {
	if h.closed {
		return nil
	}
	h.closed = true
	close(h.closeChan) // this will exit all background goroutines
	return nil
}

// PrintTable print the ARP table to stdout.
func (h *Handler) PrintTable() {
	h.arpMutex.Lock()
	defer h.arpMutex.Unlock()
	for _, v := range h.huntList {
		Logger.Msg("hunting").Struct(v).Write()
	}
}

// ProcessPacket process an ARP packet
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
func (h *Handler) ProcessPacket(frame packet.Frame) error {
	if frame.PayloadID != packet.PayloadARP {
		return packet.ErrParseFrame
	}
	arpFrame := ARP(frame.Payload())
	if err := arpFrame.IsValid(); err != nil {
		return err
	}

	// skip link local packets
	if arpFrame.SrcIP().IsLinkLocalUnicast() || arpFrame.DstIP().IsLinkLocalUnicast() {
		if Logger.IsDebug() {
			Logger.Msg("skipping link local packet").Struct(arpFrame).Write()
		}
		return nil
	}

	var operation int
	switch {
	case arpFrame.Operation() == OperationReply:
		operation = reply
	case arpFrame.Operation() == OperationRequest:
		switch {
		case arpFrame.SrcIP() == arpFrame.DstIP():
			operation = announcement
		case arpFrame.SrcIP() == packet.IPv4zero:
			operation = probe
		default:
			operation = request
		}
	default:
		Logger.Msg("invalid operation").Struct(arpFrame).Write()
		return nil
	}

	switch operation {
	case request:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| EthDstMAC | EthSRCMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | request    | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  targetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Logger.IsDebug() {
			Logger.NewLine(module, "request rcvd").MAC("ethSrc", frame.SrcAddr.MAC).MAC("ethDst", frame.DstAddr.MAC).Struct(arpFrame).Write()
		}
		// if we are spoofing the src host and the src host is trying to discover the router IP,
		// reply on behalf of the router
		h.arpMutex.Lock()
		_, hunting := h.huntList[string(arpFrame.SrcMAC())]
		h.arpMutex.Unlock()
		if hunting && arpFrame.DstIP() == h.session.NICInfo.RouterAddr4.IP {
			if Logger.IsDebug() {
				Logger.Msg("router spoofing - send reply I am").IP("ip", arpFrame.DstIP()).MAC("dstmac", arpFrame.SrcMAC()).Write()
			}
			if err := h.Reply(arpFrame.SrcMAC(), packet.Addr{MAC: h.session.NICInfo.HostAddr4.MAC, IP: arpFrame.DstIP()}, packet.Addr{MAC: arpFrame.SrcMAC(), IP: arpFrame.SrcIP()}); err != nil {
				Logger.Msg("failed to send spoofing reply").MAC("mac", arpFrame.SrcMAC()).Error(err).Write()
			}
			return nil
		}

	case probe:
		// We are interested in probe ACD (Address Conflict Detection) packets for IPs that we have an open DHCP offer
		// if this is a probe, the sender IP will be zeros; send ARP reply to stop sender from acquiring the IP
		//
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| EthDstMAC | EthSrcMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Logger.IsDebug() {
			Logger.NewLine(module, "probe rcvd").MAC("ethSrc", frame.SrcAddr.MAC).MAC("ethDst", frame.DstAddr.MAC).Struct(arpFrame).Write()
		}

		// if dhcpv4 spoofing then reject any other ip that is not the spoofed IP on offer
		if offer := h.session.DHCPv4IPOffer(arpFrame.SrcMAC()); offer.Is4() && offer != arpFrame.DstIP() {
			// Note: detected one situation where android probed external DNS IP. Not sure if this occur in other clients.
			//       to avoid issues, check DstIP is in the local subnet.
			//       arp  : probe reject for ip=8.8.8.8 from mac=84:11:9e:03:89:c0 (android phone) - 10 March 2021
			if h.session.NICInfo.HomeLAN4.Contains(arpFrame.DstIP()) {
				Logger.Msg("probe reject for").IP("ip", arpFrame.DstIP()).MAC("fromMAC", arpFrame.SrcMAC()).IP("offer", offer).Write()
				// unicast reply to srcMAC
				h.Reply(arpFrame.SrcMAC(), packet.Addr{MAC: h.session.NICInfo.HostAddr4.MAC, IP: arpFrame.DstIP()}, packet.Addr{MAC: arpFrame.SrcMAC(), IP: packet.IP4Broadcast})
			}
		}
		return nil

	case announcement:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| EthDstMAC | EthSrcMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Logger.IsDebug() {
			Logger.NewLine(module, "announcement rcvd").MAC("ethSrc", frame.SrcAddr.MAC).MAC("ethDst", frame.DstAddr.MAC).Struct(arpFrame).Write()
		}

	default:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| EthDstMAC | EthSrcMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | reply      | 2 | clientMAC | targetMAC | targetMAC  | targetIP   | clientMAC         |  clientIP |
		// | gratuitous | 2 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Logger.IsDebug() {
			Logger.NewLine(module, "reply rcvd").MAC("ethSrc", frame.SrcAddr.MAC).MAC("ethDst", frame.DstAddr.MAC).Struct(arpFrame).Write()
		}
	}
	return nil
}
