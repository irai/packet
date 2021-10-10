package icmp6

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
	"golang.org/x/net/ipv6"
)

type ICMP6 []byte

// IsValid validates the packet
// TODO: verify checksum?
func (p ICMP6) IsValid() bool {
	return len(p) >= 8
}

func (p ICMP6) Type() uint8      { return uint8(p[0]) }
func (p ICMP6) Code() uint8      { return p[1] }
func (p ICMP6) Checksum() uint16 { return binary.BigEndian.Uint16(p[2:4]) }

// TODO: fix the order
func (p ICMP6) SetChecksum(cs uint16) { p[3] = uint8(cs >> 8); p[2] = uint8(cs) }
func (p ICMP6) RestOfHeader() []byte  { return p[4:8] }
func (p ICMP6) Payload() []byte {
	if len(p) > 8 {
		return p[8:]
	}
	return []byte{}
}

func (p ICMP6) String() string {
	l := fastlog.NewLine("", "")
	return l.Struct(p).ToString()
}

// Print implements fastlog interface
func (p ICMP6) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint8("type", p.Type())
	line.Uint8("code", p.Code())
	line.Uint16Hex("checksum", p.Checksum())
	line.Int("len", len(p.Payload()))
	return line
}

type ICMPEcho []byte

func (p ICMPEcho) IsValid() bool    { return len(p) >= 8 }
func (p ICMPEcho) Type() uint8      { return uint8(p[0]) }
func (p ICMPEcho) Code() uint8      { return uint8(p[1]) }
func (p ICMPEcho) Checksum() uint16 { return binary.BigEndian.Uint16(p[2:4]) }
func (p ICMPEcho) EchoID() uint16   { return binary.BigEndian.Uint16(p[4:6]) }
func (p ICMPEcho) EchoSeq() uint16  { return binary.BigEndian.Uint16(p[6:8]) }
func (p ICMPEcho) EchoData() []byte {
	if len(p) > 8 {
		return p[8:]
	}
	return nil
}

func (p ICMPEcho) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

func (p ICMPEcho) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint8("type", p.Type())
	line.Uint8("code", p.Code())
	line.Uint16Hex("checksum", p.Checksum())
	line.Uint16Hex("id", p.EchoID())
	line.Uint16Hex("seq", p.EchoSeq())
	line.ByteArray("data", p.EchoData())
	return line
}

type ICMP6RouterSolicitation []byte

func (p ICMP6RouterSolicitation) IsValid() error {
	if len(p) < 8 {
		return packet.ErrFrameLen
	}
	if p[0] != byte(ipv6.ICMPTypeRouterSolicitation) {
		return packet.ErrParseFrame
	}
	return nil
}

func (p ICMP6RouterSolicitation) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

func (p ICMP6RouterSolicitation) FastLog(line *fastlog.Line) *fastlog.Line {
	line.String("type", "ra")
	line.Uint8("code", p.Code())
	line.MAC("sourceLLA", p.SourceLLA())
	return line
}

func (p ICMP6RouterSolicitation) Type() uint8   { return uint8(p[0]) }
func (p ICMP6RouterSolicitation) Code() byte    { return p[1] }
func (p ICMP6RouterSolicitation) Checksum() int { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP6RouterSolicitation) SourceLLA() net.HardwareAddr {
	// RS options may containg a single SourceLLA option
	// len is therefore: 26 = 4 bytes header + 4 bytes reserved + 2 bytes option header + 16 IP bytes SourceLLA option
	if len(p) >= 26 && p[8] == 1 && p[9] == 3 { // type == SourceLLA & 24 bytes len (3 * 8bytes)
		return net.HardwareAddr(p[10 : 10+16])
	}
	return nil
}

func (p ICMP6RouterSolicitation) Options() (NewOptions, error) {
	if len(p) <= 24 {
		return NewOptions{}, nil
	}
	return newParseOptions(p[24:])
}

type ICMP6RouterAdvertisement []byte

func (p ICMP6RouterAdvertisement) IsValid() bool { return len(p) >= 16 }
func (p ICMP6RouterAdvertisement) String() string {
	return fmt.Sprintf("type=ra code=%v hopLim=%d managed=%t other=%t preference=%d lifetimeSec=%d reacheableMSec=%d retransmitMSec=%d",
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

type ICMP6NeighborAdvertisement []byte

func (p ICMP6NeighborAdvertisement) IsValid() bool { return len(p) >= 24 }

func (p ICMP6NeighborAdvertisement) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

// Print implements fastlog interface
func (p ICMP6NeighborAdvertisement) FastLog(line *fastlog.Line) *fastlog.Line {
	line.String("type", "na")
	line.Uint8("code", p.Code())
	line.Bool("override", p.Override())
	line.Bool("solicited", p.Solicited())
	line.Bool("router", p.Solicited())
	line.IP("targetIP", p.TargetAddress())
	line.MAC("targetLLA", p.TargetLLA())
	return line
}

func (p ICMP6NeighborAdvertisement) Type() uint8           { return uint8(p[0]) }
func (p ICMP6NeighborAdvertisement) Code() byte            { return p[1] }
func (p ICMP6NeighborAdvertisement) Checksum() int         { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP6NeighborAdvertisement) Router() bool          { return (p[4] & 0x80) != 0 }
func (p ICMP6NeighborAdvertisement) Solicited() bool       { return (p[4] & 0x40) != 0 }
func (p ICMP6NeighborAdvertisement) Override() bool        { return (p[4] & 0x20) != 0 }
func (p ICMP6NeighborAdvertisement) TargetAddress() net.IP { return net.IP(p[8:24]) }
func (p ICMP6NeighborAdvertisement) TargetLLA() net.HardwareAddr {
	// TargetLLA option
	if len(p) < 32 || p[24] != 2 || p[25] != 1 { // Option type TargetLLA, len 8 bytes
		return nil
	}
	return net.HardwareAddr(p[26 : 26+6])
}

func ICMP6NeighborAdvertisementMarshal(router bool, solicited bool, override bool, targetAddr packet.Addr) []byte {
	b := make([]byte, 32)
	b[0] = byte(ipv6.ICMPTypeNeighborAdvertisement)
	if router {
		b[4] |= (1 << 7)
	}
	if solicited {
		b[4] |= (1 << 6)
	}
	if override {
		b[4] |= (1 << 5)
	}
	copy(b[8:], targetAddr.IP)   // target ip address
	b[24] = 2                    // option type 2 - target addr
	b[25] = 1                    // len = 1 (8 bytes)
	copy(b[26:], targetAddr.MAC) // target mac addr
	return b
}

type ICMP6NeighborSolicitation []byte

func (p ICMP6NeighborSolicitation) IsValid() bool { return len(p) >= 24 }

func (p ICMP6NeighborSolicitation) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

// Print implements fastlog interface
func (p ICMP6NeighborSolicitation) FastLog(line *fastlog.Line) *fastlog.Line {
	line.String("type", "ns")
	line.Uint8("code", p.Code())
	line.IP("targetIP", p.TargetAddress())
	line.MAC("sourceLLA", p.SourceLLA())
	return line
}

func (p ICMP6NeighborSolicitation) Type() uint8           { return uint8(p[0]) }
func (p ICMP6NeighborSolicitation) Code() byte            { return p[1] }
func (p ICMP6NeighborSolicitation) Checksum() int         { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP6NeighborSolicitation) TargetAddress() net.IP { return net.IP(p[8:24]) }
func (p ICMP6NeighborSolicitation) SourceLLA() net.HardwareAddr {
	// SourceLLA option
	if len(p) < 32 || p[24] != 1 || p[25] != 1 { // Option type TargetLLA, len 8 bytes
		return nil
	}
	return net.HardwareAddr(p[26 : 26+6])
}

func ICMP6NeighborSolicitationMarshal(targetAddr net.IP, sourceLLA net.HardwareAddr) ([]byte, error) {
	b := make([]byte, 32)                          // 4 header + 28 bytes
	b[0] = byte(ipv6.ICMPTypeNeighborSolicitation) // NS
	// skip reserved 4 bytes
	copy(b[8:], targetAddr)

	// single option: SourceLLA option
	b[24] = 2 // Target option
	b[25] = 1 // len 8 bytes
	copy(b[26:], sourceLLA)
	return b, nil
}

type ICMP6Redirect []byte

func (p ICMP6Redirect) IsValid() bool { return len(p) >= 40 }
func (p ICMP6Redirect) String() string {
	return fmt.Sprintf("type=na code=%d targetIP=%s targetMAC=%s dstIP=%s", p.Code(), p.TargetAddress(), p.TargetLinkLayerAddr(), p.DstAddress())
}
func (p ICMP6Redirect) Type() uint8           { return uint8(p[0]) }
func (p ICMP6Redirect) Code() byte            { return p[1] }
func (p ICMP6Redirect) Checksum() int         { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP6Redirect) TargetAddress() net.IP { return net.IP(p[8:24]) }
func (p ICMP6Redirect) DstAddress() net.IP    { return net.IP(p[24:40]) }
func (p ICMP6Redirect) TargetLinkLayerAddr() net.HardwareAddr {
	// TargetLLA option
	if len(p) < 40+8 || p[40] != 2 || p[41] != 1 { // Option type TargetLLA, len 8 bytes
		return nil
	}
	return net.HardwareAddr(p[42 : 42+6])
}
