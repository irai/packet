package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/irai/packet/fastlog"
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
	EthBroadcast     = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	IP4Broadcast     = net.IPv4(255, 255, 255, 255)
	IP4BroadcastAddr = Addr{MAC: EthBroadcast, IP: IP4Broadcast}

	Eth4AllNodesMulticast = net.HardwareAddr{0x01, 0x00, 0x5e, 0, 0, 0x01}
	IP4AllNodesMulticast  = net.IPv4(224, 0, 0, 1)
	IP4AllNodesAddr       = Addr{MAC: Eth4AllNodesMulticast, IP: IP4AllNodesMulticast}

	Eth4RoutersMulticast   = net.HardwareAddr{0x01, 0x00, 0x5e, 0, 0, 0x02}
	IP4AllRoutersMulticast = net.IPv4(224, 0, 0, 2)

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

// IPv6NewULA create a universal local address
// Usefule to create a IPv6 prefix when there is no global IPv6 routing
func IPv6NewULA(mac net.HardwareAddr, subnet uint16) (*net.IPNet, error) {
	prefix, err := rfc4193.Generate(mac)
	if err != nil {
		return nil, err
	}
	return prefix.Subnet(subnet).IPNet(), nil
}

// IPv6NewLLA produce a local link layer address with an EUI-64 value for mac.
// Reference: https://packetlife.net/blog/2008/aug/4/eui-64-ipv6/.
func IPv6NewLLA(mac net.HardwareAddr) net.IP {
	if len(mac) != 6 {
		fmt.Printf("packet: error in ipv6newlla invalid mac=%s\n", mac)
		return nil
	}
	ip := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0, 0}
	ip[11] = 0xff
	ip[12] = 0xfe
	copy(ip[8:], mac[:3])
	copy(ip[13:], mac[3:])
	ip[8] ^= 0x02
	return CopyIP(ip)
}

// Ethernet packet types - ETHER_TYPE
const (

	// ICMP Packet types
	ICMPTypeEchoReply   = 0
	ICMPTypeEchoRequest = 8

	IP6HeaderLen = 40 // IP6 header len
)

// Sentinel errors
var (
	ErrInvalidLen    = errors.New("invalid len")
	ErrPayloadTooBig = errors.New("payload too big")
	ErrParseFrame    = errors.New("failed to parse frame")
	ErrFrameLen      = errors.New("invalid frame length")
	ErrInvalidConn   = errors.New("invalid connection")
	ErrInvalidIP     = errors.New("invalid ip")
	ErrInvalidMAC    = errors.New("invalid mac")
	ErrInvalidIP6LLA = errors.New("invalid ip6 lla")
	ErrNotFound      = errors.New("not found")
	ErrTimeout       = errors.New("timeout")
	ErrNotRedirected = errors.New("not redirected")
	ErrIsRouter      = errors.New("host is router")
	ErrNoReader      = errors.New("no reader")
)

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

// Print implements fastlog struct interface
func (p IP4) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Int("version", p.Version())
	line.IP("src", p.Src())
	line.IP("dst", p.Dst())
	line.Int("proto", p.Protocol())
	line.Int("ttl", p.TTL())
	line.Int("tos", p.TOS())
	return line
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
	if cap(p)-len(p) < len(b) {
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

// Print implements fastlog interface
func (p UDP) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint16("srcport", p.SrcPort())
	line.Uint16("dstport", p.DstPort())
	line.Int("len", int(p.Len()))
	line.Int("payloadlen", len(p.Payload()))
	return line
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
	if cap(p)-len(p) < len(b) {
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
