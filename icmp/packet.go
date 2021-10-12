package icmp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
	"golang.org/x/net/ipv6"
)

// ICMP enable access to ICMP frame without copying
type ICMP []byte

// IsValid validates the packet
// TODO: verify checksum?
func (p ICMP) IsValid() bool {
	return len(p) >= 8
}
func (p ICMP) Type() uint8      { return uint8(p[0]) }
func (p ICMP) Code() uint8      { return p[1] }
func (p ICMP) Checksum() uint16 { return binary.BigEndian.Uint16(p[2:4]) }

// TODO: fix the order
func (p ICMP) SetChecksum(cs uint16) { p[3] = uint8(cs >> 8); p[2] = uint8(cs) }
func (p ICMP) RestOfHeader() []byte  { return p[4:8] }
func (p ICMP) Payload() []byte {
	if len(p) > 8 {
		return p[8:]
	}
	return []byte{}
}

func (p ICMP) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

// Print implements fastlog interface
func (p ICMP) FastLog(line *fastlog.Line) *fastlog.Line {
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

type ICMP4Redirect []byte

/*
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Num Addrs   |Addr Entry Size|           Lifetime            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Router Address[1]                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Preference Level[1]                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Router Address[2]                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Preference Level[2]                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               .                               |
|                               .                               |
|                               .                               |
**/

func (p ICMP4Redirect) IsValid() error {
	if len(p) < 8 || len(p) < 8+int(p.NumAddrs())*int(p.AddrSize())*4 {
		fmt.Println("TRACE    ", len(p), p.NumAddrs(), p.AddrSize())
		return packet.ErrFrameLen
	}
	if p[0] != byte(ipv6.ICMPTypeRedirect) {
		return packet.ErrParseFrame
	}
	if p.AddrSize() != 4 && p.AddrSize() != 10 {
		return packet.ErrParseFrame
	}
	return nil
}

func (p ICMP4Redirect) Type() uint8      { return uint8(p[0]) }
func (p ICMP4Redirect) Code() byte       { return p[1] }
func (p ICMP4Redirect) Checksum() uint16 { return binary.BigEndian.Uint16(p[2:4]) }
func (p ICMP4Redirect) NumAddrs() uint8  { return p[4] }
func (p ICMP4Redirect) AddrSize() uint8  { return p[5] } // The number of 32-bit words per each router address (ie. 2 for IP4)
func (p ICMP4Redirect) Lifetime() uint16 { return binary.BigEndian.Uint16(p[6:8]) }
func (p ICMP4Redirect) Addrs() []net.IP {
	addr := make([]net.IP, 0, p.NumAddrs())
	for i := 0; i < int(p.NumAddrs()); i++ {
		pos := i * int(p.AddrSize()) * 4
		if p.AddrSize() == 4 {
			addr = append(addr, net.IP(p[pos:pos+4]))
			continue
		}
		addr = append(addr, net.IP(p[pos:pos+16]))
	}
	return addr
}

func (p ICMP4Redirect) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

func (p ICMP4Redirect) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint8("type", p.Type())
	line.Uint8("code", p.Code())
	line.Uint16Hex("checksum", p.Checksum())
	line.Uint8("naddrs", p.NumAddrs())
	line.Uint8("addrsize", p.AddrSize())
	line.Uint16("lifetime", p.Lifetime())
	line.Uint16("lifetime", p.Lifetime())
	line.IPArray("addrs", p.Addrs())
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

func (p ICMP6RouterSolicitation) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

func (p ICMP6RouterSolicitation) FastLog(line *fastlog.Line) *fastlog.Line {
	line.String("type", "ra")
	line.Uint8("code", p.Code())
	line.MAC("sourceLLA", p.SourceLLA())
	return line
}

type ICMP6RouterAdvertisement []byte

func (p ICMP6RouterAdvertisement) IsValid() bool              { return len(p) >= 16 }
func (p ICMP6RouterAdvertisement) Type() uint8                { return uint8(p[0]) }
func (p ICMP6RouterAdvertisement) Code() byte                 { return p[1] }
func (p ICMP6RouterAdvertisement) Checksum() int              { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP6RouterAdvertisement) CurrentHopLimit() byte      { return p[4] }
func (p ICMP6RouterAdvertisement) ManagedConfiguration() bool { return (p[5] & 0x80) != 0 }
func (p ICMP6RouterAdvertisement) OtherConfiguration() bool   { return (p[5] & 0x40) != 0 }
func (p ICMP6RouterAdvertisement) HomeAgent() bool            { return (p[5] & 0x20) != 0 } // HomeAgent for mobile IPv6?
func (p ICMP6RouterAdvertisement) Preference() byte           { return (p[5] & 0x18) >> 3 } // Default route preference: 01 High, 00 medium, 11 low, 10 reserved
func (p ICMP6RouterAdvertisement) ProxyFlag() bool            { return (p[5] & 0x04) != 0 } // Experimental ND proxy - proxy ARP like???
func (p ICMP6RouterAdvertisement) Flags() byte                { return p[5] }               // All flags
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
func (p ICMP6RouterAdvertisement) String() string {
	// return fmt.Sprintf("type=ra code=%v hopLim=%d flags=0x%x managed=%t other=%t preference=%d lifetimeSec=%d reacheableMSec=%d retransmitMSec=%d",
	// p.Code(), p.CurrentHopLimit(), p.Flags(), p.ManagedConfiguration(), p.OtherConfiguration(), p.Preference(), p.Lifetime(), p.ReachableTime(), p.RetransmitTimer())
	return fastlog.NewLine("", "").Struct(p).ToString()
}
func (p ICMP6RouterAdvertisement) FastLog(l *fastlog.Line) *fastlog.Line {
	l.String("type", "ra")
	l.Uint8("code", p.Code())
	l.Uint8("hoplim", p.CurrentHopLimit())
	l.Uint8Hex("flags", p.Flags())
	l.Bool("managed", p.ManagedConfiguration())
	l.Bool("other", p.OtherConfiguration())
	l.Uint8("preference", p.Preference())
	l.Uint16("lifetimesec", p.Lifetime())
	l.Uint32("reacheablemsec", p.ReachableTime())
	l.Uint32("retransmitmsec", p.RetransmitTimer())
	return l
}

type ICMP6NeighborAdvertisement []byte

func (p ICMP6NeighborAdvertisement) IsValid() bool         { return len(p) >= 24 }
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

func (p ICMP6NeighborSolicitation) IsValid() bool         { return len(p) >= 24 }
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

func (p ICMP6NeighborSolicitation) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

// FastLog implements fastlog interface
func (p ICMP6NeighborSolicitation) FastLog(line *fastlog.Line) *fastlog.Line {
	line.String("type", "ns")
	line.Uint8("code", p.Code())
	line.IP("targetIP", p.TargetAddress())
	line.MAC("sourceLLA", p.SourceLLA())
	return line
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

func (p ICMP6Redirect) IsValid() bool         { return len(p) >= 40 }
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
func (p ICMP6Redirect) String() string {
	return fmt.Sprintf("type=na code=%d targetIP=%s targetMAC=%s dstIP=%s", p.Code(), p.TargetAddress(), p.TargetLinkLayerAddr(), p.DstAddress())
}
