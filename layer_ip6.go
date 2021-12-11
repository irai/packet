package packet

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/irai/packet/fastlog"
	"github.com/mdlayher/netx/rfc4193"
)

const (
	IP6HeaderLen = 40 // IP6 header len
)

// IP6 structure: see https://github.com/golang/net/blob/master/ipv6/header.go
type IP6 []byte

func (p IP6) IsValid() error {
	if len(p) >= IP6HeaderLen && int(p.PayloadLen()+IP6HeaderLen) == len(p) {
		return nil
	}
	return fmt.Errorf("invalid ipv6 len=%d: %w", len(p), ErrFrameLen)
}

// checkIPv6 verifies that ip is an IPv6 address.
func checkIPv6(ip net.IP) error {
	if ip.To16() == nil || ip.To4() != nil {
		return fmt.Errorf("ndp: invalid IPv6 address: %q", ip.String())
	}

	return nil
}

func (p IP6) Version() int       { return int(p[0]) >> 4 }                                // protocol version
func (p IP6) TrafficClass() int  { return int(p[0]&0x0f)<<4 | int(p[1])>>4 }              // traffic class
func (p IP6) FlowLabel() int     { return int(p[1]&0x0f)<<16 | int(p[2])<<8 | int(p[3]) } // flow label
func (p IP6) PayloadLen() uint16 { return binary.BigEndian.Uint16(p[4:6]) }               // payload length
func (p IP6) NextHeader() uint8  { return p[6] }                                          // next header
func (p IP6) HopLimit() uint8    { return p[7] }                                          // hop limit
func (p IP6) Src() net.IP        { return net.IP(p[8:24]) }                               // source address
func (p IP6) Dst() net.IP        { return net.IP(p[24:40]) }                              // destination address
func (p IP6) Payload() []byte    { return p[40:] }
func (p IP6) HeaderLen() int     { return 40 }
func (p IP6) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

// Print implements fastlog struct interface
func (p IP6) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Int("version", p.Version())
	line.IP("src", p.Src())
	line.IP("dst", p.Dst())
	line.Uint8("nextHeader", p.NextHeader())
	line.Uint16("len", p.PayloadLen())
	line.Uint8("hopLimit", p.HopLimit())
	line.Int("class", p.TrafficClass())
	return line
}

func IP6MarshalBinary(p []byte, hopLimit uint8, srcIP net.IP, dstIP net.IP) IP6 {
	if p == nil || cap(p) < IP6HeaderLen {
		p = make([]byte, IP6HeaderLen) // enough capacity for a max IP6 frame
	}
	p = p[:IP6HeaderLen] // change slice in case slice is less than 40

	var class int = 0
	var flow int = 0
	p[0] = 0x60 | uint8(class>>4) // first 4 bits: 6 indicates ipv6, 4 indicates ipv4
	p[1] = uint8(class<<4) | uint8(flow>>16)
	p[2] = uint8(flow >> 8)
	p[3] = uint8(flow)
	binary.BigEndian.PutUint16(p[4:6], 0)
	p[6] = 59 // 59 indicates there is no payload
	p[7] = hopLimit
	copy(p[8:24], srcIP)
	copy(p[24:40], dstIP)
	return IP6(p)
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

// HopByHopExtensionHeader describes and IPv6 hop by hop extension
// see https://tools.ietf.org/html/rfc8200
type HopByHopExtensionHeader []byte

func (p HopByHopExtensionHeader) IsValid() bool {
	if len(p) < 2 {
		return false
	}
	if len(p) < p.Len()+2 { // include 1 byte nextHeader + 1 byte len
		return false
	}
	return true
}

func (p HopByHopExtensionHeader) NextHeader() uint8 { return p[0] }
func (p HopByHopExtensionHeader) Len() int          { return int(p[1])*8 + 8 } // whole packet len - min 8 bytes (i.e p[1] does not include first 8 octets)
func (p HopByHopExtensionHeader) Data() []byte      { return p[2:p.Len()] }    //

// ParseHopByHopExtensions returns a map of icmp6 hop by hop extensions
// TODO: finish parse ipv6 options
func (p HopByHopExtensionHeader) ParseHopByHopExtensions() (ext map[int][]byte, err error) {

	data := p.Data()
	pos := 0
	for i := 0; ; i++ {
		buffer := data[pos:]
		if len(buffer) < 1 {
			fmt.Printf("ip6   : error in extension index=%d pos=%d len=%d data=\"% x\"\n", i, pos, len(buffer), p.Data())
			return nil, ErrParseFrame
		}

		// for IANA option types: see https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
		t := buffer[0] & 0b00011111 // last 5 bits contain type
		switch t {
		case 0: // padding 1
			pos = pos + 1
		case 1: // pad N
			if len(buffer) < 2 {
				fmt.Printf("ip6   : error in extension pad N len=%d\n", len(buffer))
				return nil, ErrParseFrame
			}

			// for n bytes of padding, len contains n - 2 (i.e. it discounts type and len bytes)
			pos = pos + int(buffer[1]) + 2
		case 5: // router alert
			// See https://tools.ietf.org/html/rfc2711
			if len(buffer) < 4 {
				fmt.Printf("ip6   : error in router alert option len=%d\n", len(buffer))
				return nil, ErrParseFrame
			}
			value := binary.BigEndian.Uint16(buffer[2 : 2+2])
			pos = pos + 4 // fixed len 4

			switch value {
			case 0: // packet contains MLD message
			case 1: // packet contains RSVP message
			case 2: // packet contains an active network message
			default:
				fmt.Printf("ip6   : unexpected router alert value=%d", value)
			}

		case 194: // jumbo payload
			pos = pos + 4
		default:
			fmt.Printf("ip6   : unexpected hop by hop option type=%d data=\"% x\"\n", t, p.Data())
			if len(buffer) < 2 {
				fmt.Printf("ip6   : error in unexpected extension len=%d", len(buffer))
				return nil, ErrParseFrame
			}
			pos = pos + int(buffer[1]) + 2
		}

		if pos >= len(data) {
			break
		}
	}
	return nil, nil
}

func IsIP6(ip net.IP) bool {
	if ip.To16() != nil && ip.To4() == nil {
		return true
	}
	return false
}

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
