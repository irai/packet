package icmp6

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/irai/packet/raw"
)

var (
	IP6AllNodesMulticast = net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	EthAllNodesMulticast = net.HardwareAddr{0x33, 0x33, 0, 0, 0, 0x01}
	EthRoutersMulticast  = net.HardwareAddr{0x33, 0x33, 0, 0, 0, 0x02}

	AllNodesAddr = raw.Addr{MAC: EthAllNodesMulticast, IP: IP6AllNodesMulticast}
)

type ICMP6 []byte

// IsValid validates the packet
// TODO: verify checksum?
func (p ICMP6) IsValid() bool {
	if len(p) > 8 {
		return true
	}
	return false
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
	case raw.ICMPTypeEchoReply:
		return fmt.Sprintf("echo reply code=%v id=%v data=%v", p.EchoID(), p.Code(), string(p.EchoData()))
	case raw.ICMPTypeEchoRequest:
		return fmt.Sprintf("echo request code=%v id=%v data=%v", p.EchoID(), p.Code(), string(p.EchoData()))
	}
	return fmt.Sprintf("type=%v code=%v", p.Type(), p.Code())
}
