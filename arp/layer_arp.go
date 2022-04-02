package arp

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

// ARP Operation types
const (
	OperationRequest = 1
	OperationReply   = 2
)

// ARP provides access to ARP fields without copying the structure.
type ARP []byte

// arpLen length is header + 2 * MACs + 2 IPs
// in theory MAC and IP len can vary
const arpLen = 8 + 2*6 + 2*4

func (b ARP) IsValid() error {
	if len(b) < arpLen {
		return packet.ErrFrameLen
	}
	if b.HType() != 1 {
		return packet.ErrParseFrame
	}
	if b.Proto() != syscall.ETH_P_IP {
		return packet.ErrParseProtocol
	}
	if b.HLen() != 6 {
		return packet.ErrInvalidLen
	}
	if b.PLen() != 4 {
		return packet.ErrInvalidLen
	}

	return nil
}

func (b ARP) HType() uint16            { return binary.BigEndian.Uint16(b[0:2]) }
func (b ARP) Proto() uint16            { return binary.BigEndian.Uint16(b[2:4]) }
func (b ARP) HLen() uint8              { return b[4] }
func (b ARP) PLen() uint8              { return b[5] }
func (b ARP) Operation() uint16        { return binary.BigEndian.Uint16(b[6:8]) }
func (b ARP) SrcMAC() net.HardwareAddr { return net.HardwareAddr(b[8:14]) }
func (b ARP) SrcIP() netip.Addr        { return netip.AddrFrom4(*(*[4]byte)(b[14:18])) }
func (b ARP) DstMAC() net.HardwareAddr { return net.HardwareAddr(b[18:24]) }
func (b ARP) DstIP() netip.Addr        { return netip.AddrFrom4(*(*[4]byte)(b[24:28])) }
func (b ARP) String() string           { return fastlog.NewLine("", "").Struct(b).ToString() }

func (b ARP) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint16("operation", b.Operation())
	line.MAC("srcMAC", b.SrcMAC())
	line.IP("srcIP", b.SrcIP())
	line.MAC("dstMAC", b.DstMAC())
	line.IP("dstIP", b.DstIP())
	return line
}

// EncodeARP creates a wire ARP frame ready for transmission
// see format: https://en.wikipedia.org/wiki/Address_Resolution_Protocol
func EncodeARP(b []byte, operation uint16, srcAddr packet.Addr, dstAddr packet.Addr) ARP {
	if cap(b) < arpLen {
		panic("invalid arp buffer")
	}
	b = b[:arpLen] // change the slice to accomodate the index below in case slice is less than arpLen

	binary.BigEndian.PutUint16(b[0:2], 1)                // Hardware Type - Ethernet is 1
	binary.BigEndian.PutUint16(b[2:4], syscall.ETH_P_IP) // Protocol type - IPv4 0x0800
	b[4] = 6                                             // mac len - fixed
	b[5] = 4                                             // ipv4 len - fixed
	binary.BigEndian.PutUint16(b[6:8], operation)        // operation - 1 request, 2 reply
	copy(b[8:8+6], srcAddr.MAC[:6])
	copy(b[14:14+4], srcAddr.IP.AsSlice())
	copy(b[18:18+6], dstAddr.MAC[:6])
	copy(b[24:24+4], dstAddr.IP.AsSlice())
	return b
}

func (h *Handler) RequestTo(dst net.HardwareAddr, targetIP netip.Addr) error {
	if !targetIP.Is4() {
		return packet.ErrInvalidIP
	}
	if Logger.IsDebug() {
		Logger.Msg("send request - who is").IP("ip", targetIP).IP("tell", h.session.NICInfo.HostAddr4.IP).MAC("dst", dst).Write()
	}
	return h.RequestRaw(dst, h.session.NICInfo.HostAddr4, packet.Addr{MAC: packet.EthernetBroadcast, IP: targetIP})
}

// Request send ARP request from host to targetIP
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
	arp := EncodeARP(ether.Payload(), OperationRequest, sender, target)
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
	arp := EncodeARP(ether.Payload(), OperationReply, sender, target)
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

	// Copy underneath array so we can modify value.
	ip := h.session.NICInfo.HomeLAN4.Addr()

	for host := 1; host < 255; host++ {
		// ip[3] = byte(host)
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
