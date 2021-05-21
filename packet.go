package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/mdlayher/netx/rfc4193"
	"golang.org/x/net/ipv4"
	"inet.af/netaddr"
)

// Global variables
var (
	Debug    bool
	DebugIP6 bool
	DebugIP4 bool
	DebugUDP bool

	// An IP host group address is mapped to an Ethernet multicast address
	// by placing the low-order 23-bits of the IP address into the low-order
	// 23 bits of the Ethernet multicast address 01-00-5E-00-00-00 (hex).
	EthBroadcast          = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	Eth4AllNodesMulticast = net.HardwareAddr{0x01, 0x00, 0x5e, 0, 0, 0x01}
	IP4AllNodesMulticast  = net.IPv4(224, 0, 0, 1)

	Eth4RoutersMulticast   = net.HardwareAddr{0x01, 0x00, 0x5e, 0, 0, 0x02}
	IP4AllRoutersMulticast = net.IPv4(224, 0, 0, 2)
	IP4AllNodesAddr        = Addr{MAC: Eth4AllNodesMulticast, IP: IP4AllNodesMulticast}

	Eth6AllNodesMulticast = net.HardwareAddr{0x33, 0x33, 0, 0, 0, 0x01}
	IP6AllNodesMulticast  = net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	IP6AllNodesAddr       = Addr{MAC: Eth6AllNodesMulticast, IP: IP6AllNodesMulticast}

	Eth6AllRoutersMulticast = net.HardwareAddr{0x33, 0x33, 0, 0, 0, 0x02}
	IP6AllRoutersMulticast  = net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	IP6AllRoutersAddr       = Addr{MAC: Eth6AllRoutersMulticast, IP: IP6AllRoutersMulticast}

	IP6DefaultRouter = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
)

// CLoudFlare family
// https://developers.cloudflare.com/1.1.1.1/1.1.1.1-for-families
var (
	CloudFlareDNS1       = net.IPv4(1, 1, 1, 2) // malware
	CloudFlareDNS2       = net.IPv4(1, 0, 0, 2) // malware
	CloudFlareFamilyDNS1 = net.IPv4(1, 1, 1, 3) // malware and adult sites
	CloudFlareFamilyDNS2 = net.IPv4(1, 0, 0, 3) // malware and adult sites

	// OpenDNS
	OpenDNS1 = net.IPv4(208, 67, 222, 123)
	OpenDNS2 = net.IPv4(208, 67, 220, 123)
)

// DHCP4 port numbers
const (
	DHCP4ServerPort = 67
	DHCP4ClientPort = 68
)

func IPv6SolicitedNode(lla net.IP) Addr {
	lla = lla.To16()
	return Addr{
		IP:  net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, lla[13], lla[14], lla[15]}, // prefix: 0xff, 0x02::0x01,0xff + last 3 bytes of mac address
		MAC: net.HardwareAddr{0x33, 0x33, 0xff, lla[13], lla[14], lla[15]},                        // prefix: 0x33, 0x33 + last 4 bytes of IP address
	}
}

// GenerateULA creates a universal local address
// Usefule to create a IPv6 prefix when there is no global IPv6 routing
func GenerateULA(mac net.HardwareAddr, subnet uint16) (*net.IPNet, error) {
	prefix, err := rfc4193.Generate(mac)
	if err != nil {
		return nil, err
	}
	return prefix.Subnet(subnet).IPNet(), nil
}

// Ethernet packet types - ETHER_TYPE
const (
	EthType8021AD = 0x88a8 // VLAN 802.1ad

	// Maximum ethernet II frame size is 1518 = 14 header + 1500 data + 4 CRC
	// see: https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
	EthMaxSize = 1518

	// ICMP Packet types
	ICMPTypeEchoReply   = 0
	ICMPTypeEchoRequest = 8

	IP6HeaderLen = 40 // IP6 header len
)

// Sentinel errors
var (
	ErrInvalidLen    = errors.New("invalid len")
	ErrPayloadTooBig = errors.New("payload too big")
	ErrParseMessage  = errors.New("failed to parse message")
	ErrInvalidConn   = errors.New("invalid connection")
	ErrInvalidIP     = errors.New("invalid ip")
	ErrInvalidIP6LLA = errors.New("invalid ip6 lla")
	ErrNotFound      = errors.New("not found")
	ErrTimeout       = errors.New("timeout")
	ErrNotRedirected = errors.New("not redirected")
	ErrIsRouter      = errors.New("host is router")
	ErrNoReader      = errors.New("no reader")
)

// Ether provide access to ethernet fields without copying the structure
// see: https://medium.com/@mdlayher/network-protocol-breakdown-ethernet-and-go-de985d726cc1
//
// The header features destination and source MAC addresses (each six octets in length), the EtherType field and,
// optionally, an IEEE 802.1Q tag or IEEE 802.1ad tag.
//
// The EtherType field is two octets long and it can be used for two different purposes.
// Values of 1500 and below mean that it is used to indicate the size of the payload in octets,
// while values of 1536 and above indicate that it is used as an EtherType,
// to indicate which protocol is encapsulated in the payload of the frame.
// When used as EtherType, the length of the frame is determined by the location of the interpacket gap
// and valid frame check sequence (FCS).

type Ether []byte

func (p Ether) IsValid() bool {
	// Minimum len to contain two hardware address and EtherType (2 bytes)
	return len(p) >= 14
}

func (p Ether) Dst() net.HardwareAddr { return net.HardwareAddr(p[:6]) }
func (p Ether) Src() net.HardwareAddr { return net.HardwareAddr(p[6 : 6+6]) }
func (p Ether) EtherType() uint16     { return binary.BigEndian.Uint16(p[12:14]) } // same pos as PayloadLen
func (p Ether) Payload() []byte {

	if p.EtherType() == syscall.ETH_P_IP || p.EtherType() == syscall.ETH_P_IPV6 || p.EtherType() == syscall.ETH_P_ARP {
		// fmt.Println("DEBUG: arp payload ", len(p), cap(p))
		if len(p) <= 14 { // change p in case the payload is empty
			p = p[:cap(p)]
		}
		return p[14:]
	}
	// The IEEE 802.1Q tag, if present, then two EtherType contains the Tag Protocol Identifier (TPID) value of 0x8100
	// and true EtherType/Length is located after the Q-tag.
	// The TPID is followed by two octets containing the Tag Control Information (TCI) (the IEEE 802.1p priority (quality of service) and VLAN id).
	// also handle 802.1ad - 0x88a8
	if p.EtherType() == syscall.ETH_P_8021Q { // add 2 bytes to frame
		if len(p) <= 16 { // change p in case the payload is empty
			p = p[:cap(p)]
		}
		return p[16:]
	}

	if p.EtherType() == EthType8021AD { // add 6 bytes to frame
		if len(p) <= 20 { // change p in case the payload is empty
			p = p[:cap(p)]
		}
		return p[20:]
	}
	if len(p) <= 14 { // change p in case the payload is empty
		p = p[:cap(p)]
	}
	return p[14:]
}

func (p Ether) SetPayload(payload []byte) (Ether, error) {
	return p[:len(p)+len(payload)], nil
}

func (p Ether) AppendPayload(payload []byte) (Ether, error) {
	if len(payload)+14 > cap(p) { //must be enough capcity to store header + payload
		return nil, ErrPayloadTooBig
	}
	copy(p.Payload()[:cap(payload)], payload)
	return p[:14+len(payload)], nil
}

func (p Ether) String() string {
	var b strings.Builder
	b.Grow(80)
	b.WriteString("type=")
	fmt.Fprintf(&b, "%d", p.EtherType())
	b.WriteString(" src=")
	b.WriteString(p.Src().String())
	b.WriteString(" dst=")
	b.WriteString(p.Dst().String())
	b.WriteString(" len=")
	fmt.Fprintf(&b, "%d", len(p))
	return b.String()
}

// EtherMarshalBinary creates a ethernet frame in at b using the values
// It automatically allocates a buffer if b is nil or not sufficient to store a full len ethernet packet
func EtherMarshalBinary(b []byte, hType uint16, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr) Ether {
	if b == nil || cap(b) < 14 {
		panic("ether buffer too small")
	}
	b = b[:14] // change slice in case slice is less than 14
	copy(b[0:6], dstMAC)
	copy(b[6:6+6], srcMAC)
	binary.BigEndian.PutUint16(b[12:14], hType)
	return Ether(b)
}

func IsIP6(ip net.IP) bool {
	if ip.To16() != nil && ip.To4() == nil {
		return true
	}
	return false
}

// IP4 provide access to IP fields without copying data.
// see: ipv4.ParseHeader in https://raw.githubusercontent.com/golang/net/master/ipv4/header.go
type IP4 []byte

func (p IP4) IsValid() bool {
	if len(p) < 20 {
		return false
	}

	if len(p) < p.IHL() {
		return false
	}
	return true
}

func (p IP4) IHL() int               { return int(p[0]&0x0f) << 2 } // Internet header length
func (p IP4) Version() int           { return int(p[0] >> 4) }
func (p IP4) Protocol() int          { return int(p[9]) }
func (p IP4) TOS() int               { return int(p[1]) }
func (p IP4) ID() int                { return int(binary.BigEndian.Uint16(p[4:6])) }
func (p IP4) TTL() int               { return int(p[8]) }
func (p IP4) Checksum() int          { return int(binary.BigEndian.Uint16(p[10:12])) }
func (p IP4) Src() net.IP            { return net.IPv4(p[12], p[13], p[14], p[15]) }
func (p IP4) Dst() net.IP            { return net.IPv4(p[16], p[17], p[18], p[19]) }
func (p IP4) NetaddrDst() netaddr.IP { return netaddr.IPv4(p[16], p[17], p[18], p[19]) }
func (p IP4) TotalLen() int          { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p IP4) Payload() []byte        { return p[p.IHL():] }
func (p IP4) String() string {
	return fmt.Sprintf("version=%v src=%v dst=%v proto=%v ttl=%v tos=%v", p.Version(), p.Src(), p.Dst(), p.Protocol(), p.TTL(), p.TOS())
}

func IP4MarshalBinary(p []byte, ttl byte, src net.IP, dst net.IP) IP4 {
	options := []byte{}
	var hdrLen = ipv4.HeaderLen + len(options) // len includes options
	const fragOffset = 0
	const flags = 0
	const totalLen = ipv4.HeaderLen + 0 // 0 payload
	const id = 0
	const protocol = 0 // invalid
	const checksum = 0

	flagsAndFragOff := (fragOffset & 0x1fff) | int(flags<<13)
	if src = src.To4(); src == nil {
		src = net.IPv4zero
	}
	if dst = dst.To4(); dst == nil {
		dst = net.IPv4zero
	}

	p[0] = byte(ipv4.Version<<4 | (hdrLen >> 2 & 0x0f))
	p[1] = byte(0xc0) // DSCP CS6)
	binary.BigEndian.PutUint16(p[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(p[4:6], uint16(id))
	binary.BigEndian.PutUint16(p[6:8], uint16(flagsAndFragOff))
	p[8] = byte(ttl)
	p[9] = byte(protocol)
	binary.BigEndian.PutUint16(p[10:12], uint16(checksum))
	copy(p[12:16], src[:net.IPv4len])
	copy(p[16:20], dst[:net.IPv4len])
	return p[:ipv4.HeaderLen]
}

func (p IP4) SetPayload(b []byte, protocol byte) IP4 {
	p[9] = protocol
	totalLen := uint16(ipv4.HeaderLen + len(b))
	binary.BigEndian.PutUint16(p[2:4], totalLen)
	checksum := p.CalculateChecksum()
	p[11] = byte(checksum >> 8)
	p[10] = byte(checksum)
	return b[:totalLen]
}

func (p IP4) AppendPayload(b []byte, protocol byte) (IP4, error) {
	if b == nil || cap(p)-len(p) < len(b) {
		return nil, ErrPayloadTooBig
	}
	p = p[:len(p)+len(b)] // change slice in case slice is less than required
	copy(p.Payload(), b)
	p[9] = protocol
	totalLen := uint16(ipv4.HeaderLen + len(b))
	binary.BigEndian.PutUint16(p[2:4], totalLen)
	checksum := p.CalculateChecksum()
	p[11] = byte(checksum >> 8)
	p[10] = byte(checksum)
	return p, nil
}

func (p IP4) CalculateChecksum() uint16 {
	psh := make([]byte, 20)
	copy(psh[0:10], p[0:10])           // first 10 bytes
	copy(psh[10:10+8], p[10+2:10+2+8]) // skip checksum filed in pos 10
	return Checksum(psh)
}

type ICMP4 []byte

func (p ICMP4) IsValid() bool {
	return len(p) > 8
}

func (p ICMP4) Type() uint8          { return uint8(p[0]) }
func (p ICMP4) Code() uint8          { return p[1] }
func (p ICMP4) Checksum() uint16     { return binary.BigEndian.Uint16(p[2:4]) }
func (p ICMP4) RestOfHeader() []byte { return p[4:8] }
func (p ICMP4) Payload() []byte      { return p[8:] }
func (p ICMP4) String() string {
	return fmt.Sprintf("type=%v code=%v payloadLen=%d, data=0x% x", p.Type(), p.Code(), len(p.Payload()), p.Payload())
}

type ICMPEcho []byte

func (p ICMPEcho) IsValid() bool   { return len(p) >= 8 }
func (p ICMPEcho) Type() uint8     { return uint8(p[0]) }
func (p ICMPEcho) Code() int       { return int(p[1]) }
func (p ICMPEcho) Checksum() int   { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMPEcho) EchoID() uint16  { return binary.BigEndian.Uint16(p[4:6]) }
func (p ICMPEcho) EchoSeq() uint16 { return binary.BigEndian.Uint16(p[6:8]) }
func (p ICMPEcho) EchoData() string {
	if len(p) > 8 {
		return string(p[8:])
	}
	return ""
}
func (p ICMPEcho) String() string {
	return fmt.Sprintf("type=%v id=%v code=%v dlen=%v, data=0x% x", p.Type(), p.EchoID(), p.Code(), len(p.EchoData()), p.EchoData())
}

func ICMPEchoBinary(b []byte, id uint16, seq uint16, data []byte) []byte {
	binary.BigEndian.PutUint16(b[:2], id)
	binary.BigEndian.PutUint16(b[2:4], seq)
	copy(b[4:], data)
	return b
}

// Checksum calculate IP4, ICMP6 checksum - is this the same for TCP?
// In network format already
// TODO: fix this to work with big endian
func Checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}

const UDPHeaderLen = 8

type UDP []byte

func (p UDP) String() string {
	return fmt.Sprintf("srcport=%d dstport=%d len=%d payloadlen=%d", p.SrcPort(), p.DstPort(), p.Len(), len(p.Payload()))
}

func (p UDP) SrcPort() uint16  { return binary.BigEndian.Uint16(p[0:2]) }
func (p UDP) DstPort() uint16  { return binary.BigEndian.Uint16(p[2:4]) }
func (p UDP) Len() uint16      { return binary.BigEndian.Uint16(p[4:6]) }
func (p UDP) Checksum() uint16 { return binary.BigEndian.Uint16(p[6:8]) }
func (p UDP) Payload() []byte  { return p[8:] }

func (p UDP) IsValid() bool {
	return len(p) >= 8 // 8 bytes UDP header
}

func UDPMarshalBinary(p []byte, srcPort uint16, dstPort uint16) UDP {
	if p == nil || cap(p) < UDPHeaderLen {
		p = make([]byte, EthMaxSize) // enough capacity for a max ethernet
	}
	p = p[:UDPHeaderLen] // change slice in case slice is less than header

	binary.BigEndian.PutUint16(p[0:2], srcPort)
	binary.BigEndian.PutUint16(p[2:4], dstPort)
	binary.BigEndian.PutUint16(p[4:6], 0) // len zero - no payload
	return UDP(p)
}

func (p UDP) SetPayload(b []byte) UDP {
	binary.BigEndian.PutUint16(p[4:6], UDPHeaderLen+uint16(len(b)))
	// no checksum for IP4
	return p[:len(p)+len(b)]
}

func (p UDP) AppendPayload(b []byte) (UDP, error) {
	if b == nil || cap(p)-len(p) < len(b) {
		return nil, ErrPayloadTooBig
	}
	p = p[:len(p)+len(b)] // change slice in case slice is less total
	copy(p.Payload(), b)
	binary.BigEndian.PutUint16(p[4:6], UDPHeaderLen+uint16(len(b)))
	// no checksum for IP4
	return p, nil
}

// For future usage: See tcp header
// https://github.com/grahamking/latency
type TCP []byte

func (p TCP) IsValid() bool {
	return len(p) >= 20
}

func (p TCP) SrcPort() uint16  { return binary.BigEndian.Uint16(p[0:2]) }
func (p TCP) DstPort() uint16  { return binary.BigEndian.Uint16(p[2:4]) }
func (p TCP) Seq() uint32      { return binary.BigEndian.Uint32(p[4:8]) }
func (p TCP) Ack() uint32      { return binary.BigEndian.Uint32(p[8:12]) }
func (p TCP) HeaderLen() int   { return int(p[12] >> 4) }
func (p TCP) NS() bool         { return p[12]&0x01 != 0 }
func (p TCP) FIN() bool        { return p[13]&0x01 != 0 }
func (p TCP) SYN() bool        { return p[13]&0x02 != 0 }
func (p TCP) RST() bool        { return p[13]&0x04 != 0 }
func (p TCP) PSH() bool        { return p[13]&0x08 != 0 }
func (p TCP) ACK() bool        { return p[13]&0x10 != 0 }
func (p TCP) URG() bool        { return p[13]&0x20 != 0 }
func (p TCP) ECE() bool        { return p[13]&0x40 != 0 }
func (p TCP) CWR() bool        { return p[13]&0x80 != 0 }
func (p TCP) Window() uint16   { return binary.BigEndian.Uint16(p[14:16]) }
func (p TCP) Checksum() uint16 { return binary.BigEndian.Uint16(p[16:18]) }
func (p TCP) Urgent() uint16   { return binary.BigEndian.Uint16(p[18:20]) }
func (p TCP) Payload() []byte  { return p[p[12]>>4:] }
