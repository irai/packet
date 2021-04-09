package icmp6

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/irai/packet"
)

type ICMP6 []byte

// IsValid validates the packet
// TODO: verify checksum?
func (p ICMP6) IsValid() bool {
	return len(p) > 8
}

func (p ICMP6) Type() uint8      { return uint8(p[0]) }
func (p ICMP6) Code() uint8      { return p[1] }
func (p ICMP6) Checksum() uint16 { return binary.BigEndian.Uint16(p[2:4]) }

// TODO: fix the order
func (p ICMP6) SetChecksum(cs uint16) { p[3] = uint8(cs >> 8); p[2] = uint8(cs) }
func (p ICMP6) RestOfHeader() []byte  { return p[4:8] }
func (p ICMP6) Payload() []byte       { return p[8:] }
func (p ICMP6) String() string {
	return fmt.Sprintf("type=%v code=%v checksum=%x payloadLen=%v\n", p.Type(), p.Code(), p.Checksum(), len(p.Payload()))
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

	switch p.Type() {
	case packet.ICMPTypeEchoReply:
		return fmt.Sprintf("echo reply code=%v id=%v data=%v", p.EchoID(), p.Code(), string(p.EchoData()))
	case packet.ICMPTypeEchoRequest:
		return fmt.Sprintf("echo request code=%v id=%v data=%v", p.EchoID(), p.Code(), string(p.EchoData()))
	}
	return fmt.Sprintf("type=%v code=%v", p.Type(), p.Code())
}

type ICMP6RouterAdvertisement []byte

func (p ICMP6RouterAdvertisement) IsValid() bool { return len(p) >= 16 }
func (p ICMP6RouterAdvertisement) String() string {
	return fmt.Sprintf("type=ra code=%v hopLim=%v managed=%v other=%v preference=%v lifetimeSec=%v reacheableMSec=%v retransmitMSec=%v",
		p.Code(), p.CurrentHopLimit(), p.ManagedConfiguration(), p.OtherConfiguration(), p.Preference(), p.Lifetime(), p.ReachableTime(), p.RetransmitTimer())
}
func (p ICMP6RouterAdvertisement) Type() uint8                { return uint8(p[0]) }
func (p ICMP6RouterAdvertisement) Code() byte                 { return p[1] }
func (p ICMP6RouterAdvertisement) Checksum() int              { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP6RouterAdvertisement) CurrentHopLimit() byte      { return p[4] }
func (p ICMP6RouterAdvertisement) ManagedConfiguration() bool { return (p[5] & 0x80) != 0 }
func (p ICMP6RouterAdvertisement) OtherConfiguration() bool   { return (p[5] & 0x40) != 0 }
func (p ICMP6RouterAdvertisement) HomeAgent() bool            { return (p[5] & 0x20) != 0 } // HomeAgent for mobile IPv6?
func (p ICMP6RouterAdvertisement) Preference() byte           { return (p[5] & 0x18) >> 3 } // Default route preference: 01 High, 00 medium, 11 low, 10 reserved
func (p ICMP6RouterAdvertisement) ProxyFlag() bool            { return (p[5] & 0x04) != 0 } // Experimental ND proxy - proxy ARP like???
func (p ICMP6RouterAdvertisement) Lifetime() (seconds uint16) { return binary.BigEndian.Uint16(p[6:8]) }
func (p ICMP6RouterAdvertisement) ReachableTime() (milliseconds uint32) {
	return binary.BigEndian.Uint32(p[8:12])
}
func (p ICMP6RouterAdvertisement) RetransmitTimer() (milliseconds uint32) {
	return binary.BigEndian.Uint32(p[12:16])
}
func (p ICMP6RouterAdvertisement) Options() (NewOptions, error) {
	if len(p) <= 16 {
		return NewOptions{}, nil
	}
	return newParseOptions(p[16:])
}

type NewOptions struct {
	MTU              MTU
	Prefices         []PrefixInformation
	RDNSS            RecursiveDNSServer
	SourceLLA        LinkLayerAddress
	TargetLLA        LinkLayerAddress
	DNSSearchList    DNSSearchList
	RouteInformation RouteInformation
}

func newParseOptions(b []byte) (NewOptions, error) {
	var options NewOptions

	for i := 0; len(b[i:]) != 0; {
		// Two bytes: option type and option length.
		if len(b[i:]) < 2 {
			return NewOptions{}, io.ErrUnexpectedEOF
		}

		// Type processed as-is, but length is stored in units of 8 bytes,
		// so expand it to the actual byte length.
		t := b[i]
		l := int(b[i+1]) * 8

		// Verify that we won't advance beyond the end of the byte slice.
		if l > len(b[i:]) {
			return NewOptions{}, io.ErrUnexpectedEOF
		}

		// Infer the option from its type value and use it for unmarshaling.
		switch t {
		case optSourceLLA:
			if err := options.SourceLLA.unmarshal(b[i : i+l]); err != nil {
				return NewOptions{}, err
			}
		case optTargetLLA:
			if err := options.TargetLLA.unmarshal(b[i : i+l]); err != nil {
				return NewOptions{}, err
			}
		case optMTU:
			if err := options.MTU.unmarshal(b[i : i+l]); err != nil {
				return NewOptions{}, err
			}
		case optPrefixInformation:
			p := PrefixInformation{}
			if err := p.unmarshal(b[i : i+l]); err != nil {
				return NewOptions{}, err
			}
			options.Prefices = append(options.Prefices, p)
		case optRouteInformation:
			if err := options.RouteInformation.unmarshal(b[i : i+l]); err != nil {
				return NewOptions{}, err
			}
		case optRDNSS:
			if err := options.RDNSS.unmarshal(b[i : i+l]); err != nil {
				return NewOptions{}, err
			}
		case optDNSSL:
			if err := options.DNSSearchList.unmarshal(b[i : i+l]); err != nil {
				return NewOptions{}, err
			}
		default:
			fmt.Println("icmp6 : invalid option - ignoring ", t)
		}

		// Advance to the next option's type field.
		i += l
	}

	return options, nil
}
