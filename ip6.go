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

type HopByHopExtension []byte

func (p HopByHopExtension) IsValid() bool {
	if len(p) < 2 {
		return false
	}
	if len(p) < p.Len()+2 {
		return false

	}

	return true
}

func (p HopByHopExtension) Action() uint8 { return p[0] >> 6 }
func (p HopByHopExtension) Change() uint8 { return (p[0] & 0b00111111) >> 5 }
func (p HopByHopExtension) Type() uint8   { return p[0] & 0b00011111 }
func (p HopByHopExtension) Len() int      { return int(p[1]) }
func (p HopByHopExtension) Data() []byte  { return p[2 : p.Len()+2] }

// ProcessPacket handles icmp6 packets
func (h *Handler) ProcessIP6HopByHopExtension(host *Host, b []byte) (n int, err error) {

	ether := Ether(b)
	ip6Frame := IP6(ether.Payload())
	ip6Option := HopByHopExtension(ip6Frame.Payload())

	var optionLen int
	for i := 0; len(ip6Option) > 0; i++ {
		if !ip6Option.IsValid() {
			return 0, fmt.Errorf("invalid ipv6 hop by hop option pos=%d msg=%v: %w", i, ip6Frame, ErrParseMessage)
		}

		data := ip6Option.Data()
		switch ip6Option.Type() {
		case 0: // padding
		case 1: // pad N
		case 5: // router alert
			// See https://tools.ietf.org/html/rfc2711
			if n := len(data); n != 2 {
				fmt.Printf("ip6   : error in router alert option len=%d", n)
				return 0, ErrParseMessage
			}
			value := binary.BigEndian.Uint16(data[2 : 2+2])
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
		}
		optionLen = optionLen + ip6Option.Len()
		ip6Option = ip6Option[ip6Option.Len():]
	}

	return optionLen, nil
}
