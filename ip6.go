package packet

import (
	"encoding/binary"
	"fmt"
	"net"
)

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

func (p HopByHopExtensionHeader) NextHeader() int { return int(p[0]) }
func (p HopByHopExtensionHeader) Len() int        { return int(p[1])*8 + 8 } // whole packet len - min 8 bytes (i.e p[1] does not include first 8 octets)
func (p HopByHopExtensionHeader) Data() []byte    { return p[2:p.Len()] }    //

// ProcessPacket handles icmp6 packets
func (h *Handler) ProcessIP6HopByHopExtension(host *Host, b []byte, header []byte) (n int, err error) {

	// ether := Ether(b)
	// ip6Frame := IP6(ether.Payload())
	ip6HopExtensionHeader := HopByHopExtensionHeader(header)
	if !ip6HopExtensionHeader.IsValid() {
		return 0, ErrParseMessage
	}

	data := ip6HopExtensionHeader.Data()
	pos := 0
	for i := 0; ; i++ {
		buffer := data[pos:]
		if len(buffer) < 1 {
			fmt.Printf("ip6   : error in extension index=%d pos=%d len=%d data=\"% x\"\n", i, pos, len(buffer), ip6HopExtensionHeader.Data())
			return 0, ErrParseMessage
		}

		// for IANA option types: see https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
		t := buffer[0] & 0b00011111 // last 5 bits contain type
		switch t {
		case 0: // padding 1
			pos = pos + 1
			fmt.Println("TRACE got single padding")
		case 1: // pad N
			if len(buffer) < 2 {
				fmt.Printf("ip6   : error in extension pad N len=%d\n", len(buffer))
				return 0, ErrParseMessage
			}
			fmt.Println("TRACE got pad N padding", int(buffer[1]))

			// for n bytes of padding, len contains n - 2 (i.e. it discounts type and len bytes)
			pos = pos + int(buffer[1]) + 2
		case 5: // router alert
			// See https://tools.ietf.org/html/rfc2711
			if len(buffer) < 4 {
				fmt.Printf("ip6   : error in router alert option len=%d\n", n)
				return 0, ErrParseMessage
			}
			value := binary.BigEndian.Uint16(buffer[2 : 2+2])
			pos = pos + 4 // fixed len 4

			if Debug {
				fmt.Printf("ip6   : hop by hop option router alert value=%d\n", value)
			}
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
			fmt.Printf("ip6   : unexpected hop by hop option type=%d data=\"% x\"\n", t, ip6HopExtensionHeader.Data())
			if len(buffer) < 2 {
				fmt.Printf("ip6   : error in unexpected extension len=%d", len(buffer))
				return 0, ErrParseMessage
			}
			pos = pos + int(buffer[1]) + 2
		}

		if pos >= len(data) {
			break
		}
	}

	return pos, nil
}
