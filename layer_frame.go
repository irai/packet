package packet

import (
	"bytes"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/irai/packet/fastlog"
)

//go:generate stringer -type=PayloadID
type PayloadID int

const (
	PayloadEther         PayloadID = 1
	Payload8023          PayloadID = 2
	PayloadARP           PayloadID = 3
	PayloadIP4           PayloadID = 4
	PayloadIP6           PayloadID = 5
	PayloadICMP4         PayloadID = 6
	PayloadICMP6         PayloadID = 7
	PayloadUDP           PayloadID = 8
	PayloadTCP           PayloadID = 9
	PayloadDHCP4         PayloadID = 10
	PayloadDHCP6         PayloadID = 11
	PayloadDNS           PayloadID = 12
	PayloadMDNS          PayloadID = 13
	PayloadSSL           PayloadID = 14
	PayloadNTP           PayloadID = 15
	PayloadSSDP          PayloadID = 16
	PayloadWSDP          PayloadID = 17
	PayloadNBNS          PayloadID = 18
	PayloadPlex          PayloadID = 19
	PayloadUbiquiti      PayloadID = 20
	PayloadLLMNR         PayloadID = 21
	PayloadIGMP          PayloadID = 22
	PayloadEthernetPause PayloadID = 23
	PayloadRRCP          PayloadID = 24
	PayloadLLDP          PayloadID = 25
	Payload802_11r       PayloadID = 26
	PayloadIEEE1905      PayloadID = 27
	PayloadSonos         PayloadID = 28
	Payload880a          PayloadID = 29
)

// Frame describes a network packet and the various protocol layers within it.
// It maintains a reference to common protocols like IP4, IP6, UDP, TCP.
type Frame struct {
	ether         Ether     // reference the full packet
	offsetIP4     int       // offset to IP4 packet
	offsetIP6     int       // offset to IP6 packet
	offsetUDP     int       // offset to UDP packet
	offsetTCP     int       // offset to TCP packet
	offsetPayload int       // offset to rest of payload
	PayloadID     PayloadID // protocol ID for value in payload
	SrcAddr       Addr      // reference to source IP, MAC and Port number (if available)
	DstAddr       Addr      // reference to destination IP, MAC and Port number (if available)
	Session       *Session  // session where frame was capture
	Host          *Host     // pointer to Host entry for this IP address
	flags         uint      // processing flags : online_transition (0x01), offline_transition (0x02)
}

func (frame Frame) onlineTransition() bool     { return frame.flags&0x01 == 0x01 }
func (frame Frame) markOnlineTransition() uint { return frame.flags | 0b01 }

func (frame Frame) offlineTransition() bool    { return frame.flags&0x02 == 0x02 }
func (frame Frame) setOfflineTransition() uint { return frame.flags | 0b10 }

func (frame Frame) Log(line *fastlog.Line) *fastlog.Line {
	line.String("payloadID", frame.PayloadID.String())
	line.MAC("srcMAC", frame.SrcAddr.MAC)
	line.IP("srcIP", frame.SrcAddr.IP)
	line.MAC("dstMAC", frame.DstAddr.MAC)
	line.IP("dstIP", frame.DstAddr.IP)
	line.Int("payloadlen", len(frame.Payload()))
	if frame.Host != nil {
		line.Bool("captured", frame.Host.MACEntry.Captured)
	}
	return line
}

func (f Frame) Ether() Ether {
	return f.ether
}

// ARP returns a reference to the ARP packet or nil if this is not an ARP packet.
func (f Frame) ARP() ARP {
	if f.PayloadID == PayloadARP {
		return ARP(f.ether[f.offsetPayload:])
	}
	return nil
}

// HasIP returns true if the packet contains either an IPv4 or IPv6 frame.
func (f Frame) HasIP() bool {
	return (f.offsetIP4 != 0 || f.offsetIP6 != 0)
}

// IP4 returns a reference to the IP4 packet or nil if this is not an IPv4 packet.
func (f Frame) IP4() IP4 {
	if f.offsetIP4 != 0 {
		return IP4(f.ether[f.offsetIP4:])
	}
	return nil
}

// IP6 returns a reference to the IP6 packet or nil if this is not an IPv6 packet.
func (f Frame) IP6() IP6 {
	if f.offsetIP6 != 0 {
		return IP6(f.ether[f.offsetIP6:])
	}
	return nil
}

// UDP returns a reference to the UDP packet or nil if this is not a UDP packet.
func (f Frame) UDP() UDP {
	if f.offsetUDP != 0 {
		return UDP(f.ether[f.offsetUDP:])
	}
	return nil
}

// TCP returns a reference to the TCP packet or nil if this is not a TCP packet.
func (f Frame) TCP() TCP {
	if f.offsetTCP != 0 {
		return TCP(f.ether[f.offsetTCP:])
	}
	return nil
}

// Payload retuns a reference to the last payload in the envelope. This is
// typically the application layer protocol in a UDP or TCP packet.
// Payload will always contain the last payload processed without errors.
// In case of protocol validation errors the Payload will return the last valid payload.
func (f Frame) Payload() []byte {
	if f.offsetPayload != 0 {
		return f.ether[f.offsetPayload:]
	}
	return nil
}

type ProtoStats struct {
	Proto    PayloadID
	Count    int
	ErrCount int
	Last     time.Time
}

// Parse returns a Frame containing references to common layers and the payload. It will also
// create the host entry if this is a new IP. The function is fast as it
// will map to the underlying array. No copy and no allocation takes place.
//
// Benchmark result: Jan 2021
// cpu: 11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz
// Benchmark_Parse-8
// 25281475	        47.58 ns/op	       0 B/op	       0 allocs/op
func (h *Session) Parse(p []byte) (frame Frame, err error) {
	frame.ether = p
	if err := frame.ether.IsValid(); err != nil {
		return Frame{}, err
	}
	frame.Session = h
	frame.SrcAddr.MAC = frame.ether.Src()
	frame.DstAddr.MAC = frame.ether.Dst()
	frame.PayloadID = PayloadEther
	frame.offsetPayload = frame.ether.HeaderLen()

	// Only interested in unicast ethernet
	if !IsUnicastMAC(frame.SrcAddr.MAC) {
		return frame, nil
	}

	// In order to allow Ethernet II and IEEE 802.3 framing to be used on the same Ethernet segment,
	// a unifying standard, IEEE 802.3x-1997, was introduced that required that EtherType values be greater than or equal to 1536.
	// Thus, values of 1500 and below for this field indicate that the field is used as the size of the payload of the Ethernet frame
	// while values of 1536 and above indicate that the field is used to represent an EtherType.
	if frame.ether.EtherType() < 1536 {
		frame.PayloadID = Payload8023
		return frame, nil
	}

	var proto uint8
	switch frame.ether.EtherType() {
	case syscall.ETH_P_IP:
		frame.PayloadID = PayloadIP4
		ip4 := IP4(frame.Payload())
		if err := ip4.IsValid(); err != nil {
			return frame, err
		}
		atomic.StoreUint32(&h.ipHeartBeat, 1)
		h.Statistics[PayloadIP4].Count++
		frame.offsetIP4 = frame.offsetPayload
		frame.offsetPayload = frame.offsetPayload + ip4.IHL()
		proto = ip4.Protocol()
		frame.SrcAddr.IP = ip4.Src()
		frame.DstAddr.IP = ip4.Dst()
		// create host if ip is local lan IP
		// don't create host if packets sent via our interface.
		// If we don't have this, then we received all sent and forwarded packets with client IPs containing our host mac
		if !bytes.Equal(frame.SrcAddr.MAC, h.NICInfo.HostAddr4.MAC) && frame.Session.NICInfo.HomeLAN4.Contains(frame.SrcAddr.IP) {
			frame.Host, _ = frame.Session.findOrCreateHostWithLock(frame.SrcAddr) // will lock/unlock
			if !frame.Host.Online {
				frame.Session.onlineTransition(frame.Host)
				frame.flags = frame.markOnlineTransition()
			}
		}
	case syscall.ETH_P_IPV6:
		frame.PayloadID = PayloadIP6
		ip6 := IP6(frame.Payload())
		if err := ip6.IsValid(); err != nil {
			return frame, err
		}
		atomic.StoreUint32(&h.ipHeartBeat, 1)
		h.Statistics[PayloadIP6].Count++
		proto = ip6.NextHeader()
		frame.SrcAddr.IP = ip6.Src()
		frame.DstAddr.IP = ip6.Dst()
		frame.offsetIP6 = frame.offsetPayload
		frame.offsetPayload = frame.offsetPayload + ip6.HeaderLen()
		// create host if src IP is:
		//     - unicast local link address (i.e. fe80::)
		//     - global IP6 sent by a local host not the router
		//
		// We ignore IP6 packets forwarded by the router to a local host using a Global Unique Addresses.
		// For example, an IP6 google search will be forwared by the router as:
		//    ip6 src=google.com dst=GUA localhost and srcMAC=routerMAC dstMAC=localHostMAC
		// TODO: is it better to check if IP is in the prefix?
		//
		// don't create host if packets sent via our interface.
		// If we don't have this, then we received all sent and forwarded packets with client IPs containing our host mac
		if !bytes.Equal(frame.SrcAddr.MAC, h.NICInfo.HostAddr4.MAC) &&
			(frame.SrcAddr.IP.IsLinkLocalUnicast() ||
				(frame.SrcAddr.IP.IsGlobalUnicast() && !bytes.Equal(frame.SrcAddr.MAC, frame.Session.NICInfo.RouterAddr4.MAC))) {
			frame.Host, _ = frame.Session.findOrCreateHostWithLock(frame.SrcAddr) // will lock/unlock
			if !frame.Host.Online {
				frame.Session.onlineTransition(frame.Host)
				frame.flags = frame.markOnlineTransition()
			}
		}
	case syscall.ETH_P_ARP:
		frame.PayloadID = PayloadARP
		arp := ARP(frame.Payload())
		if err := arp.IsValid(); err != nil {
			return frame, err
		}
		h.Statistics[PayloadARP].Count++

		// create host if new IP appears in arp packet
		// don't create host if packets sent via our interface.
		// If we don't have this, then we received all sent and forwarded packets with client IPs containing our host mac
		// Validates arp len and that hardware len is 6 for mac address
		srcIP := arp.SrcIP()
		if !bytes.Equal(frame.SrcAddr.MAC, h.NICInfo.HostAddr4.MAC) &&
			frame.Session.NICInfo.HomeLAN4.Contains(srcIP) {
			addr := Addr{MAC: arp.SrcMAC(), IP: srcIP}                   // use arp src mac and ip in lookup
			frame.Host, _ = frame.Session.findOrCreateHostWithLock(addr) // will lock/unlock
			if !frame.Host.Online {
				frame.Session.onlineTransition(frame.Host)
				frame.flags = frame.markOnlineTransition()
			}
		}
		return frame, nil

	case 0x8808: // Ethernet pause frame
		frame.PayloadID = PayloadEthernetPause
		h.Statistics[PayloadEthernetPause].Count++
		frame.offsetPayload = frame.Ether().HeaderLen()
		return frame, nil

	case 0x8899: // Realtek remote control protocol (RRCP)
		frame.PayloadID = PayloadRRCP
		h.Statistics[PayloadRRCP].Count++
		frame.offsetPayload = frame.Ether().HeaderLen()
		return frame, nil

	case 0x88cc: // Local link discovery protocol (LLDP)
		frame.PayloadID = PayloadLLDP
		h.Statistics[PayloadLLDP].Count++
		frame.offsetPayload = frame.Ether().HeaderLen()
		return frame, nil

	case 0x890d: // 802.11r
		frame.PayloadID = Payload802_11r
		h.Statistics[Payload802_11r].Count++
		frame.offsetPayload = frame.Ether().HeaderLen()
		return frame, nil

	case 0x893a: // IEEE 1905
		frame.PayloadID = PayloadIEEE1905
		h.Statistics[PayloadIEEE1905].Count++
		frame.offsetPayload = frame.Ether().HeaderLen()
		return frame, nil

	case 0x6970: // Sonos proprietary protocol
		frame.PayloadID = PayloadSonos
		h.Statistics[PayloadSonos].Count++
		frame.offsetPayload = frame.Ether().HeaderLen()
		return frame, nil

	case 0x880a: // not sure what this is but seen often on home LANs
		frame.PayloadID = Payload880a
		h.Statistics[Payload880a].Count++
		frame.offsetPayload = frame.Ether().HeaderLen()
		return frame, nil

	default:
		return frame, nil
	}

	switch proto {
	case syscall.IPPROTO_UDP:
		frame.PayloadID = PayloadUDP
		udp := UDP(frame.Payload())
		if err := udp.IsValid(); err != nil {
			return frame, err
		}
		h.Statistics[PayloadUDP].Count++
		frame.offsetUDP = frame.offsetPayload
		frame.SrcAddr.Port = udp.SrcPort()
		frame.DstAddr.Port = udp.DstPort()
		switch {
		default:
			return frame, nil
		case frame.SrcAddr.Port == 443 || frame.DstAddr.Port == 443: // SSL
			frame.PayloadID = PayloadSSL
			h.Statistics[PayloadSSL].Count++
		case frame.DstAddr.Port == 67 || frame.DstAddr.Port == 68: // DHCP4 packet
			frame.PayloadID = PayloadDHCP4
			h.Statistics[PayloadDHCP4].Count++
		case frame.DstAddr.Port == 546 || frame.DstAddr.Port == 547: // DHCP6
			frame.PayloadID = PayloadDHCP6
			h.Statistics[PayloadDHCP6].Count++
		case frame.SrcAddr.Port == 53 || frame.DstAddr.Port == 53: // DNS request
			frame.PayloadID = PayloadDNS
			h.Statistics[PayloadDNS].Count++
		case frame.SrcAddr.Port == 5353 || frame.DstAddr.Port == 5353: // Multicast DNS (MDNS)
			frame.PayloadID = PayloadMDNS
			h.Statistics[PayloadMDNS].Count++
		case frame.SrcAddr.Port == 5355 || frame.DstAddr.Port == 5355: // Link Local Multicast Name Resolution (LLMNR)
			frame.PayloadID = PayloadLLMNR
			h.Statistics[PayloadLLMNR].Count++
		case frame.SrcAddr.Port == 123 || frame.DstAddr.Port == 123: // NTP
			frame.PayloadID = PayloadNTP
			h.Statistics[PayloadNTP].Count++
		case frame.SrcAddr.Port == 1900 || frame.DstAddr.Port == 1900: // Microsoft Simple Service Discovery Protocol (SSDP)
			frame.PayloadID = PayloadSSDP
			h.Statistics[PayloadSSDP].Count++
		case frame.SrcAddr.Port == 3702 || frame.DstAddr.Port == 3702: // Web Services Discovery Protocol (WSD)
			frame.PayloadID = PayloadWSDP
			h.Statistics[PayloadWSDP].Count++
		case frame.DstAddr.Port == 137 || frame.DstAddr.Port == 138: // Netbions NBNS
			frame.PayloadID = PayloadNBNS
			h.Statistics[PayloadNBNS].Count++
		case frame.DstAddr.Port == 32412 || frame.DstAddr.Port == 32414: // Plex application protocol
			frame.PayloadID = PayloadPlex
			h.Statistics[PayloadPlex].Count++
		case frame.SrcAddr.Port == 10001 || frame.DstAddr.Port == 10001: // Ubiquiti device discovery protocol
			frame.PayloadID = PayloadUbiquiti
			h.Statistics[PayloadUbiquiti].Count++
		}
		frame.offsetPayload = frame.offsetPayload + udp.HeaderLen() // only update offset if known header
		return frame, nil

	case syscall.IPPROTO_TCP:
		frame.PayloadID = PayloadTCP
		tcp := TCP(frame.Payload())
		if err := tcp.IsValid(); err != nil {
			return frame, err
		}
		h.Statistics[PayloadTCP].Count++
		frame.offsetTCP = frame.offsetPayload
		frame.SrcAddr.Port = tcp.SrcPort()
		frame.DstAddr.Port = tcp.DstPort()
		return frame, nil

	case syscall.IPPROTO_ICMP:
		icmpFrame := ICMP(frame.Payload())
		if err := icmpFrame.IsValid(); err != nil {
			return frame, err
		}
		// process echo reply to unblock ping if running
		if icmpFrame.Type() == ICMP4TypeEchoReply {
			echo := ICMPEcho(icmpFrame)
			if err := echo.IsValid(); err != nil {
				return frame, err
			}
			echoNotify(echo.EchoID()) // unblock ping if waiting
		}
		frame.PayloadID = PayloadICMP4
		h.Statistics[PayloadICMP4].Count++
		return frame, nil

	case syscall.IPPROTO_ICMPV6:
		icmpFrame := ICMP(frame.Payload())
		if err := icmpFrame.IsValid(); err != nil {
			return frame, err
		}
		// process echo reply to unblock ping if running
		if icmpFrame.Type() == ICMP6TypeEchoReply {
			echo := ICMPEcho(icmpFrame)
			if err := echo.IsValid(); err != nil {
				return frame, err
			}
			echoNotify(echo.EchoID()) // unblock ping if waiting
		}
		frame.PayloadID = PayloadICMP6
		h.Statistics[PayloadICMP6].Count++
		return frame, nil

	case syscall.IPPROTO_IGMP:
		frame.PayloadID = PayloadIGMP
		h.Statistics[PayloadIGMP].Count++
		return frame, nil
	}
	return frame, nil
}

func (h *Session) onlineTransition(host *Host) {
	if host.Online {
		return
	}

	host.MACEntry.Online = true
	host.Online = true
	host.dirty = true

	var line *fastlog.Line
	if Logger.IsInfo() {
		line = Logger.Msg("IP is online").Struct(host.Addr)
	}

	if host.Addr.IP.Is4() {
		if host.Addr.IP != host.MACEntry.IP4 { // changed IP4
			if line != nil {
				line.IP("previous", host.MACEntry.IP4)
			}
			host.MACEntry.IP4 = host.Addr.IP
			for _, v := range host.MACEntry.HostList {
				if v.Addr.IP.Is4() && v.Addr.IP != host.Addr.IP {
					if v.Online {
						if Logger.IsInfo() {
							Logger.Msg("IP is offline").Struct(v.Addr).Write()
						}
						v.Online = false
						v.dirty = true
					}
				}
			}
		}
	} else {
		if host.Addr.IP.IsGlobalUnicast() && host.Addr.IP != host.MACEntry.IP6GUA { // changed IP6 global unique address
			if line != nil {
				line.IP("previous", host.MACEntry.IP6GUA)
			}
			host.MACEntry.IP6GUA = host.Addr.IP
		}
		if host.Addr.IP.IsLinkLocalUnicast() && host.Addr.IP != host.MACEntry.IP6LLA { // changed IP6 link local address
			if line != nil {
				line.IP("previous", host.MACEntry.IP6LLA)
			}
			host.MACEntry.IP6LLA = host.Addr.IP
			// don't set offline IP as we don't target LLA
		}
	}
	if line != nil {
		line.Write()
	}
}
