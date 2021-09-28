package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/irai/packet/fastlog"
)

// Ether provide access to ethernet II fields without copying the structure
// see: https://medium.com/@mdlayher/network-protocol-breakdown-ethernet-and-go-de985d726cc1
//
// The header features destination and source MAC addresses (each six octets in length), the EtherType field and,
// optionally, an IEEE 802.1Q tag or IEEE 802.1ad tag.
//
// The EtherType field is two octets long and it can be used for two different purposes.
// Values of 1500 and below mean that it is used to indicate the size of the payload in octets,
// while values of 1536 and above indicate that it is used as an EtherType,
// to indicate which protocol is encapsulated in the payload of the frame.
type Ether []byte

func (p Ether) IsValid() error {
	// Minimum len to contain two hardware address and EtherType (2 bytes) + 1 byte payload
	if len(p) >= 14 {
		return nil
	}
	return ErrFrameLen
}

func (p Ether) Dst() net.HardwareAddr { return net.HardwareAddr(p[:6]) }
func (p Ether) Src() net.HardwareAddr { return net.HardwareAddr(p[6 : 6+6]) }
func (p Ether) EtherType() uint16     { return binary.BigEndian.Uint16(p[12:14]) } // same pos as PayloadLen

func (p Ether) SrcIP() net.IP {
	switch p.EtherType() {
	case syscall.ETH_P_IP:
		return IP4(p.Payload()).Src()
	case syscall.ETH_P_IPV6:
		return IP6(p.Payload()).Src()
	}
	return nil
}

func (p Ether) DstIP() net.IP {
	switch p.EtherType() {
	case syscall.ETH_P_IP:
		return IP4(p.Payload()).Dst()
	case syscall.ETH_P_IPV6:
		return IP6(p.Payload()).Dst()
	}
	return nil
}

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
	// An Ethernet frame has a minimum size of 60 bytes because anything that is shorter is interpreted
	// by receiving station as a frame resulting from a collision.
	// pad smaller frames with zeros
	tmp := p[:len(p)+len(payload)]
	if n := len(tmp); n < 60 {
		tmp = tmp[:60]
		for n < 60 {
			tmp[n] = 0x00
			n++
		}
	}
	return tmp, nil
}

func (p Ether) AppendPayload(payload []byte) (Ether, error) {
	if len(payload)+14 > cap(p) { //must be enough capcity to store header + payload
		return nil, ErrPayloadTooBig
	}
	copy(p.Payload()[:cap(payload)], payload)

	// An Ethernet frame has a minimum size of 60 bytes because anything that is shorter is interpreted
	// by receiving station as a frame resulting from a collision.
	// pad smaller frames with zeros
	tmp := p[:14+len(payload)]
	if n := len(tmp); n < 60 {
		tmp = tmp[:60]
		for n < 60 {
			tmp[n] = 0x00
			n++
		}
	}
	return tmp, nil
}

func (p Ether) String() string {
	var b strings.Builder
	b.Grow(80)
	b.WriteString("type=0x")
	fmt.Fprintf(&b, "%x", p.EtherType())
	b.WriteString(" src=")
	b.WriteString(p.Src().String())
	b.WriteString(" dst=")
	b.WriteString(p.Dst().String())
	b.WriteString(" len=")
	fmt.Fprintf(&b, "%d", len(p))
	return b.String()
}

// Print implements fastlog struct interface
func (p Ether) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint16Hex("type", p.EtherType())
	line.MAC("src", p.Src())
	line.MAC("dst", p.Dst())
	line.Int("len", len(p))
	return line
}

// EtherMarshalBinary creates a ethernet frame in at b using the values
// It panic if b is nil or not sufficient to store a full len ethernet packet
func EtherMarshalBinary(b []byte, hType uint16, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr) Ether {
	if cap(b) < 14 {
		panic("ether buffer too small")
	}
	b = b[:14] // change slice in case slice is less than 14
	copy(b[0:6], dstMAC)
	copy(b[6:6+6], srcMAC)
	binary.BigEndian.PutUint16(b[12:14], hType)
	return Ether(b)
}

// IEEE1905 provide access to IEEE 1905 home networking frame fields
type IEEE1905 []byte

func (p IEEE1905) IsValid() error {
	if len(p) < 8 {
		return ErrFrameLen
	}
	return nil
}

func (p IEEE1905) Version() uint8    { return p[0] }
func (p IEEE1905) Reserved() uint8   { return p[1] }
func (p IEEE1905) Type() uint16      { return binary.BigEndian.Uint16(p[2:4]) }
func (p IEEE1905) ID() uint16        { return binary.BigEndian.Uint16(p[4:6]) }
func (p IEEE1905) FragmentID() uint8 { return p[6] }
func (p IEEE1905) Flags() uint8      { return p[7] }
func (p IEEE1905) TLV() []byte       { return p[8:] }

func (p IEEE1905) String() string {
	line := fastlog.NewLine("", "")
	return p.FastLog(line).ToString()
}

func (p IEEE1905) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint8("version", p.Version())
	line.Uint16Hex("type", p.Type())
	line.Uint16("id", p.ID())
	line.Uint8("fragment", p.FragmentID())
	line.Uint8Hex("flags", p.Flags())
	line.ByteArray("tlv", p.TLV())
	return line
}

// EthernetPause provide access to Ethernet pause frame fields
type EthernetPause []byte

func (p EthernetPause) IsValid() error {
	if len(p) < 46 {
		return ErrFrameLen
	}
	if p.Opcode() != 0x0001 {
		return ErrParseFrame
	}
	return nil
}

func (p EthernetPause) Opcode() uint16   { return binary.BigEndian.Uint16(p[0:2]) } // must be 0x0001
func (p EthernetPause) Duration() uint16 { return binary.BigEndian.Uint16(p[2:4]) } // typically 0x0000 or 0xffff
func (p EthernetPause) Reserved() []byte { return p[4:] }

func (p EthernetPause) String() string {
	line := fastlog.NewLine("", "")
	return p.FastLog(line).ToString()
}

func (p EthernetPause) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint16Hex("opcode", p.Opcode())
	line.Uint16Hex("duration", p.Duration())
	return line
}
