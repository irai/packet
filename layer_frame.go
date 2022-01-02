package packet

import (
	"bytes"
	"net"
	"sync/atomic"
	"syscall"
	"time"
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

type Result struct {
	Update    bool      // Set to true if update is required
	HuntStage HuntStage // DHCP4 hunt stage
	NameEntry NameEntry // Name
	SrcAddr   Addr      // reference to frame MAC, IP and Port (i.e. not copied) - the engine will copy if required
	IsRouter  bool      // Mark host as router
}

// Frame describes a network packet and the various protocol layers within it.
// It maintains a reference to common protocols like IP4, IP6, UDP, TCP.
type Frame struct {
	Ether         Ether     // slice reference to the complete packet
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
}

// ARP returns a reference to the ARP packet or nil if this is not a ARP packet.
func (f Frame) ARP() ARP {
	if f.PayloadID == PayloadARP {
		return ARP(f.Ether[f.offsetPayload:])
	}
	return nil
}

func (f Frame) IsIP() bool {
	return (f.offsetIP4 != 0 || f.offsetIP6 != 0)
}

// IP4 returns a reference to the IP4 packet or nil if this is not an IPv4 packet.
func (f Frame) IP4() IP4 {
	if f.offsetIP4 != 0 {
		return IP4(f.Ether[f.offsetIP4:])
	}
	return nil
}

// IP6 returns a reference to the IP6 packet or nil if this is not an IPv6 packet.
func (f Frame) IP6() IP6 {
	if f.offsetIP6 != 0 {
		return IP6(f.Ether[f.offsetIP6:])
	}
	return nil
}

// UDP returns a reference to the UDP packet or nil if this is not a UDP packet.
func (f Frame) UDP() UDP {
	if f.offsetUDP != 0 {
		return UDP(f.Ether[f.offsetUDP:])
	}
	return nil
}

// TCP returns a reference to the TCP packet or nil if this is not a TCP packet.
func (f Frame) TCP() TCP {
	if f.offsetTCP != 0 {
		return TCP(f.Ether[f.offsetTCP:])
	}
	return nil
}

// Payload retuns a reference to the last payload in the envelope. This is
// typically the application layer protocol in a UDP or TCP packet.
// Payload will always contain the last payload processed without errors.
// In case of protocol validation errors the Payload will return the last valid payload.
func (f Frame) Payload() []byte {
	if f.offsetPayload != 0 {
		return f.Ether[f.offsetPayload:]
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
func (h *Session) Parse(p []byte) (frame Frame, err error) {
	frame.Ether = Ether(p)
	if err := frame.Ether.IsValid(); err != nil {
		return Frame{}, err
	}
	frame.Session = h
	frame.SrcAddr.MAC = frame.Ether.Src()
	frame.DstAddr.MAC = frame.Ether.Dst()
	frame.PayloadID = PayloadEther
	frame.offsetPayload = frame.Ether.HeaderLen()

	// Only interested in unicast ethernet
	if !IsUnicastMAC(frame.SrcAddr.MAC) {
		return frame, nil
	}

	// In order to allow Ethernet II and IEEE 802.3 framing to be used on the same Ethernet segment,
	// a unifying standard, IEEE 802.3x-1997, was introduced that required that EtherType values be greater than or equal to 1536.
	// Thus, values of 1500 and below for this field indicate that the field is used as the size of the payload of the Ethernet frame
	// while values of 1536 and above indicate that the field is used to represent an EtherType.
	if frame.Ether.EtherType() < 1536 {
		frame.PayloadID = Payload8023
		return frame, nil
	}

	var proto uint8
	switch frame.Ether.EtherType() {
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
		}
	case syscall.ETH_P_ARP:
		frame.PayloadID = PayloadARP
		h.Statistics[PayloadARP].Count++
		// create host if new IP appers in arp packet
		// don't create host if packets sent via our interface.
		// If we don't have this, then we received all sent and forwarded packets with client IPs containing our host mac
		// Validates arp len and that hardware len is 6 for mac address
		if arp := frame.Payload(); len(arp) >= 28 && arp[4] == 6 {
			srcIP := net.IP(arp[14:18])
			if !bytes.Equal(frame.SrcAddr.MAC, h.NICInfo.HostAddr4.MAC) &&
				frame.Session.NICInfo.HomeLAN4.Contains(srcIP) {
				addr := Addr{MAC: net.HardwareAddr(arp[8:14]), IP: srcIP}    // src mac and src ip
				frame.Host, _ = frame.Session.findOrCreateHostWithLock(addr) // will lock/unlock
			}
		}
		return frame, nil

	case 0x8808: // Ethernet pause frame
		frame.PayloadID = PayloadEthernetPause
		h.Statistics[PayloadEthernetPause].Count++
		frame.offsetPayload = frame.Ether.HeaderLen()
		return frame, nil

	case 0x8899: // Realtek remote control protocol (RRCP)
		frame.PayloadID = PayloadRRCP
		h.Statistics[PayloadRRCP].Count++
		frame.offsetPayload = frame.Ether.HeaderLen()
		return frame, nil

	case 0x88cc: // Local link discovery protocol (LLDP)
		frame.PayloadID = PayloadLLDP
		h.Statistics[PayloadLLDP].Count++
		frame.offsetPayload = frame.Ether.HeaderLen()
		return frame, nil

	case 0x890d: // 802.11r
		frame.PayloadID = Payload802_11r
		h.Statistics[Payload802_11r].Count++
		frame.offsetPayload = frame.Ether.HeaderLen()
		return frame, nil

	case 0x893a: // IEEE 1905
		frame.PayloadID = PayloadIEEE1905
		h.Statistics[PayloadIEEE1905].Count++
		frame.offsetPayload = frame.Ether.HeaderLen()
		return frame, nil

	case 0x6970: // Sonos proprietary protocol
		frame.PayloadID = PayloadSonos
		h.Statistics[PayloadSonos].Count++
		frame.offsetPayload = frame.Ether.HeaderLen()
		return frame, nil

	case 0x880a: // not sure what this is but seen often on home LANs
		frame.PayloadID = Payload880a
		h.Statistics[Payload880a].Count++
		frame.offsetPayload = frame.Ether.HeaderLen()
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
		default:
			return frame, nil
		}
		frame.offsetPayload = frame.offsetPayload + udp.HeaderLen() // update offset if known header
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
		frame.PayloadID = PayloadICMP4
		h.Statistics[PayloadICMP4].Count++
		return frame, nil

	case syscall.IPPROTO_ICMPV6:
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
