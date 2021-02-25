package raw

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/mdlayher/netx/rfc4193"
)

var ipv6LinkLocal = func(cidr string) *net.IPNet {
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return net
}("fe80::/10")

// GenerateULA creates a universal local address
// Usefule to create a IPv6 prefix when there is no global IPv6 routing
func GenerateULA(mac net.HardwareAddr, subnet uint16) (*net.IPNet, error) {
	prefix, err := rfc4193.Generate(mac)
	if err != nil {
		return nil, err
	}
	return prefix.Subnet(subnet).IPNet(), nil
}

type PacketProcessor interface {
	ProcessPacket(*Host, []byte) error
	Start(context.Context) error
	// Stop() error
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

// EtherBuffer creates a lockable buffer to avoid mem allocation
// during send packets. Benchmark shows this technique is 20x faster than allocating each time.
type EtherBuffer struct {
	b [EthMaxSize]byte
	sync.Mutex
}

// Alloc locks and return the buffer
func (e *EtherBuffer) Alloc() Ether {
	e.Lock()
	return Ether(e.b[0:14])
}

// Free release the lock on the buffer
func (e *EtherBuffer) Free() {
	e.Unlock()
}

// Sentinel errors
var (
	ErrInvalidLen    = errors.New("invalid len")
	ErrPayloadTooBig = errors.New("payload too big")
	ErrParseMessage  = errors.New("failed to parse message")
	ErrInvalidConn   = errors.New("invalid connection")
	ErrInvalidIP4    = errors.New("invalid ip4")
	ErrNotFound      = errors.New("not found")
)

// CopyIP simply copies the IP to a new buffer with the same len - either 4 or 16
func CopyIP(srcIP net.IP) net.IP {
	ip := make(net.IP, len(srcIP))
	copy(ip, srcIP)
	return ip
}

// CopyMAC simply copies a mac address to a new buffer with the same len
func CopyMAC(srcMAC net.HardwareAddr) net.HardwareAddr {
	mac := make(net.HardwareAddr, len(srcMAC))
	copy(mac, srcMAC)
	return mac
}

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
	if len(p) < 14 {
		return false
	}
	return true
}

func (p Ether) Dst() net.HardwareAddr { return net.HardwareAddr(p[:6]) }
func (p Ether) Src() net.HardwareAddr { return net.HardwareAddr(p[6 : 6+6]) }
func (p Ether) EtherType() uint16     { return binary.BigEndian.Uint16(p[12:14]) } // same pos as PayloadLen
func (p Ether) Payload() []byte {

	if p.EtherType() == syscall.ETH_P_IP || p.EtherType() == syscall.ETH_P_IPV6 || p.EtherType() == syscall.ETH_P_ARP {
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
	return fmt.Sprintf("type=%x src=%v dst=%v len=%v", p.EtherType(), p.Src(), p.Dst(), len(p))
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

func (p IP4) IHL() int        { return int(p[0]&0x0f) << 2 } // Internet header length
func (p IP4) Version() int    { return int(p[0] >> 4) }
func (p IP4) Protocol() int   { return int(p[9]) }
func (p IP4) TOS() int        { return int(p[1]) }
func (p IP4) ID() int         { return int(binary.BigEndian.Uint16(p[4:6])) }
func (p IP4) TTL() int        { return int(p[8]) }
func (p IP4) Checksum() int   { return int(binary.BigEndian.Uint16(p[10:12])) }
func (p IP4) Src() net.IP     { return net.IPv4(p[12], p[13], p[14], p[15]) }
func (p IP4) Dst() net.IP     { return net.IPv4(p[16], p[17], p[18], p[19]) }
func (p IP4) TotalLen() int   { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p IP4) Payload() []byte { return p[p.IHL():] }
func (p IP4) String() string {
	return fmt.Sprintf("version=%v src=%v dst=%v proto=%v ttl=%v tos=%v", p.Version(), p.Src(), p.Dst(), p.Protocol(), p.TTL(), p.TOS())
}

type ICMP4 []byte

func (p ICMP4) IsValid() bool {
	if len(p) > 8 {
		return true
	}
	return false
}

func (p ICMP4) Type() uint8          { return uint8(p[0]) }
func (p ICMP4) Code() uint8          { return p[1] }
func (p ICMP4) Checksum() uint16     { return binary.BigEndian.Uint16(p[2:4]) }
func (p ICMP4) RestOfHeader() []byte { return p[4:8] }
func (p ICMP4) Payload() []byte      { return p[8:] }

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

// IP6 structure: see https://github.com/golang/net/blob/master/ipv6/header.go
type IP6 []byte

func (p IP6) IsValid() bool {
	if len(p) >= IP6HeaderLen && p.PayloadLen()+IP6HeaderLen == len(p) {
		return true
	}
	fmt.Println("warning payload differ ", len(p), p.PayloadLen()+IP6HeaderLen)
	return false
}

func (p IP6) Version() int      { return int(p[0]) >> 4 }                                // protocol version
func (p IP6) TrafficClass() int { return int(p[0]&0x0f)<<4 | int(p[1])>>4 }              // traffic class
func (p IP6) FlowLabel() int    { return int(p[1]&0x0f)<<16 | int(p[2])<<8 | int(p[3]) } // flow label
func (p IP6) PayloadLen() int   { return int(binary.BigEndian.Uint16(p[4:6])) }          // payload length
func (p IP6) NextHeader() int   { return int(p[6]) }                                     // next header
func (p IP6) HopLimit() int     { return int(p[7]) }                                     // hop limit
func (p IP6) Src() net.IP       { return net.IP(p[8:24]) }                               // source address
func (p IP6) Dst() net.IP       { return net.IP(p[24:40]) }                              // destination address
func (p IP6) Payload() []byte   { return p[40:] }
func (p IP6) String() string {
	return fmt.Sprintf("version=%v src=%v dst=%v nextHeader=%v payloadLen=%v hoplimit=%v class=%v", p.Version(), p.Src(), p.Dst(), p.NextHeader(), p.PayloadLen(), p.HopLimit(), p.TrafficClass())
}

func IP6MarshalBinary(b []byte, hopLimit uint8, srcIP net.IP, dstIP net.IP) IP6 {
	if b == nil || cap(b) < IP6HeaderLen {
		b = make([]byte, IP6HeaderLen) // enough capacity for a max IP6 frame
	}
	b = b[:IP6HeaderLen] // change slice in case slice is less than 40

	var class int = 0
	var flow int = 0
	b[0] = 0x60 | uint8(class>>4) // first 4 bits: 6 indicates ipv6, 4 indicates ipv4
	fmt.Printf("b0: %x\n", b[0])
	b[1] = uint8(class<<4) | uint8(flow>>16)
	b[2] = uint8(flow >> 8)
	b[3] = uint8(flow)
	binary.BigEndian.PutUint16(b[4:6], 0)
	b[6] = 59 // 59 indicates there is no payload
	b[7] = hopLimit
	copy(b[8:24], srcIP)
	copy(b[24:40], dstIP)
	return IP6(b)
}

func (p IP6) SetPayload(b []byte, nextHeader uint8) IP6 {
	binary.BigEndian.PutUint16(p[4:6], uint16(len(b)))
	p[6] = nextHeader
	return p[:len(p)+len(b)]
}
func (p IP6) AppendPayload(b []byte, nextHeader uint8) (IP6, error) {
	if b == nil || cap(p)-len(p) < len(b) {
		return nil, ErrPayloadTooBig
	}
	p = p[:len(p)+len(b)] // change slice in case slice is less than 40
	copy(p.Payload(), b)
	binary.BigEndian.PutUint16(p[4:6], uint16(len(b)))
	p[6] = nextHeader
	return p, nil
}

// Checksum calculate ICMP6 checksum - is this the same for TCP?
// In network format already
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
