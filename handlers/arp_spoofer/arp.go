// Package arp_spoofer provides a handler to spoof arp tables on a target host.
package arp_spoofer

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"syscall"
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

// RequestTo sends an arp request to the destination mac. This is useful
// to send a unicast request to a host.
func (h *Handler) RequestTo(dst net.HardwareAddr, targetIP netip.Addr) error {
	if !targetIP.Is4() {
		return packet.ErrInvalidIP
	}
	if Logger.IsDebug() {
		Logger.Msg("send request - who is").IP("ip", targetIP).IP("tell", h.session.NICInfo.HostAddr4.IP).MAC("dst", dst).Write()
	}
	return h.RequestRaw(dst, h.session.NICInfo.HostAddr4, packet.Addr{MAC: packet.EthernetBroadcast, IP: targetIP})
}

// Request send a broadcast ARP request from host to targetIP
func (h *Handler) Request(targetIP netip.Addr) error {
	if !targetIP.Is4() {
		return packet.ErrInvalidIP
	}
	if Logger.IsDebug() {
		Logger.Msg("send request - who is").IP("ip", targetIP).IP("tell", h.session.NICInfo.HostAddr4.IP).Write()
	}
	return h.RequestRaw(packet.EthernetBroadcast, h.session.NICInfo.HostAddr4, packet.Addr{MAC: packet.EthernetBroadcast, IP: targetIP})
}

// Probe send an arp probe broadcast on the local link.
//
// The term 'ARP Probe' is used to refer to an ARP Request packet, broadcast on the local link,
// with an all-zero 'sender IP address'. The 'sender hardware address' MUST contain the hardware address of the
// interface sending the  The 'sender IP address' field MUST be set to all zeroes,
// to avoid polluting ARP caches in other hosts on the same link in the case where the address turns out
// to be already in use by another host. The 'target IP address' field MUST be set to the address being probed.
// An ARP Probe conveys both a question ("Is anyone using this address?") and an
// implied statement ("This is the address I hope to use.").
func (h *Handler) Probe(ip netip.Addr) error {
	return h.RequestRaw(packet.EthernetBroadcast, packet.Addr{MAC: h.session.NICInfo.HostAddr4.MAC, IP: packet.IPv4zero}, packet.Addr{MAC: packet.EthernetZero, IP: ip})
}

// AnnounceTo send an arp announcement on the local link.
//
// Having probed to determine that a desired address may be used safely,
// a host implementing this specification MUST then announce that it
// is commencing to use this address by broadcasting ANNOUNCE_NUM ARP
// Announcements, spaced ANNOUNCE_INTERVAL seconds apart.  An ARP
// Announcement is identical to the ARP Probe described above, except
// that now the sender and target IP addresses are both set to the
// host's newly selected IPv4 address.  The purpose of these ARP
// Announcements is to make sure that other hosts on the link do not
// have stale ARP cache entries left over from some other host that may
// previously have been using the same address.  The host may begin
// legitimately using the IP address immediately after sending the first
// of the two ARP Announcements;
func (h *Handler) AnnounceTo(dst net.HardwareAddr, targetIP netip.Addr) (err error) {
	if Logger.IsDebug() {
		if bytes.Equal(dst, packet.EthernetBroadcast) {
			Logger.Msg("send announcement broadcast - I am").IP("ip", targetIP).Write()
		} else {
			Logger.Msg("send announcement unicast - I am").IP("ip", targetIP).MAC("dst", dst).Write()
		}
	}
	err = h.RequestRaw(dst,
		packet.Addr{MAC: h.session.NICInfo.HostAddr4.MAC, IP: targetIP},
		packet.Addr{MAC: packet.EthernetBroadcast, IP: targetIP})
	return err
}

// RequestRaw send an ARP Request packet
// multiple goroutines can call RequestRaw simultaneously.
//
// Request is almost always broadcast but unicast can be used to maintain ARP table;
// i.e. unicast polling check for stale ARP entries; useful to test online/offline state
//
// ARP: packet types
//      note that RFC 3927 specifies 00:00:00:00:00:00 for Request TargetMAC
// +============+===+===========+===========+============+============+===================+===========+
// | Type       | op| etherDST  | etherSRC  | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
// +============+===+===========+===========+============+============+===================+===========+
// | Request    | 1 | broadcast | hostMAC   | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  targetIP |
// | reply      | 2 | clientMAC | targetMAC | targetMAC  | targetIP   | clientMAC         |  clientIP |
// | gratuitous | 2 | broadcast | hostMAC   | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
// | ACD probe  | 1 | broadcast | hostMAC   | clientMAC  | 0x00       | 0x00              |  targetIP |
// | ACD announ | 1 | broadcast | hostMAC   | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
// +============+===+===========+===========+============+============+===================+===========+
//
func (h *Handler) RequestRaw(dst net.HardwareAddr, sender packet.Addr, target packet.Addr) (err error) {
	b := packet.EtherBufferPool.Get().(*[packet.EthMaxSize]byte)
	defer packet.EtherBufferPool.Put(b)
	ether := packet.Ether(b[0:])

	// Send packet with ether src set to host but arp packet set to target
	ether = packet.EncodeEther(ether, syscall.ETH_P_ARP, h.session.NICInfo.HostAddr4.MAC, dst)
	arp := packet.EncodeARP(ether.Payload(), packet.ARPOperationRequest, sender, target)
	if ether, err = ether.SetPayload(arp); err != nil {
		return err
	}

	_, err = h.session.Conn.WriteTo(ether, &packet.Addr{MAC: dst})
	return err
}

// Reply send ARP reply from the src to the dst
//
// Call with dstHwAddr = ethernet.Broadcast to reply to all
func (h *Handler) Reply(dst net.HardwareAddr, sender packet.Addr, target packet.Addr) error {
	if Logger.IsDebug() {
		Logger.Msg("send reply ip is at").IP("ip", sender.IP).MAC("mac", sender.MAC).Write()
		// fmt.Printf("arp   : send reply - ip=%s is at mac=%s\n", sender.IP, sender.MAC)
	}
	return h.reply(dst, sender, target)
}

// reply sends an ARP reply packet from src to dst.
//
// dstEther identifies the target for the Ethernet packet : i.e. use EthernetBroadcast for gratuitous ARP
func (h *Handler) reply(dst net.HardwareAddr, sender packet.Addr, target packet.Addr) (err error) {
	b := packet.EtherBufferPool.Get().(*[packet.EthMaxSize]byte)
	defer packet.EtherBufferPool.Put(b)
	ether := packet.Ether(b[0:])

	// Send packet with ether src set to host but arp packet set to target
	ether = packet.EncodeEther(ether, syscall.ETH_P_ARP, h.session.NICInfo.HostAddr4.MAC, dst)
	arp := packet.EncodeARP(ether.Payload(), packet.ARPOperationReply, sender, target)
	if ether, err = ether.SetPayload(arp); err != nil {
		return err
	}

	_, err = h.session.Conn.WriteTo(ether, &packet.Addr{MAC: dst})
	return err
}

// WhoIs will send a request packet to get the MAC address for the IP. Retry 3 times.
//
func (h *Handler) WhoIs(ip netip.Addr) (packet.Addr, error) {

	for i := 0; i < 3; i++ {
		if host := h.session.FindIP(ip); host != nil {
			return packet.Addr{IP: host.Addr.IP, MAC: host.MACEntry.MAC}, nil
		}
		if err := h.Request(ip); err != nil {
			return packet.Addr{}, err
		}
		time.Sleep(time.Millisecond * 50 * time.Duration(i+1))
	}

	if Logger.IsDebug() {
		Logger.Msg("whois not found").IP("ip", ip).Write()
		h.PrintTable()
	}
	return packet.Addr{}, packet.ErrNotFound
}

// ScanNetwork sends 256 arp requests to identify IPs on the lan
func (h *Handler) Scan() error {
	ip := h.session.NICInfo.HomeLAN4.Addr()
	n := (uint32(0xffffffff) << uint32(h.session.NICInfo.HomeLAN4.Bits())) >> h.session.NICInfo.HomeLAN4.Bits()
	for host := uint32(1); host < n; host++ {
		ip = ip.Next()

		// Don't scan router and host
		if ip == h.session.NICInfo.RouterAddr4.IP || ip == h.session.NICInfo.HostAddr4.IP {
			continue
		}

		if h.closed { // return if Close() is called when we are in the loop
			return nil
		}
		err := h.Request(ip)
		if err != nil {
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				if Logger.IsDebug() {
					Logger.Msg("error in write socket is temporary - retry ").Error(err1).Write()
				}
				continue
			}

			if Logger.IsDebug() {
				Logger.Msg("arp request error").Error(err).Write()
			}
			return err
		}
		time.Sleep(time.Millisecond * 8)
	}
	return nil
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
	arpFrame := packet.ARP(frame.Payload())
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
	case arpFrame.Operation() == packet.ARPOperationReply:
		operation = reply
	case arpFrame.Operation() == packet.ARPOperationRequest:
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
			Logger.Msg("request rcvd").MAC("ethSrc", frame.SrcAddr.MAC).MAC("ethDst", frame.DstAddr.MAC).Struct(arpFrame).Write()
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
			Logger.Msg("probe rcvd").MAC("ethSrc", frame.SrcAddr.MAC).MAC("ethDst", frame.DstAddr.MAC).Struct(arpFrame).Write()
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
			Logger.Msg("announcement rcvd").MAC("ethSrc", frame.SrcAddr.MAC).MAC("ethDst", frame.DstAddr.MAC).Struct(arpFrame).Write()
		}

	default:
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| EthDstMAC | EthSrcMAC | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | reply      | 2 | clientMAC | targetMAC | targetMAC  | targetIP   | clientMAC         |  clientIP |
		// | gratuitous | 2 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if Logger.IsDebug() {
			Logger.Msg("reply rcvd").MAC("ethSrc", frame.SrcAddr.MAC).MAC("ethDst", frame.DstAddr.MAC).Struct(arpFrame).Write()
		}
	}
	return nil
}
