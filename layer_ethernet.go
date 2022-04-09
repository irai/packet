package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"github.com/irai/packet/fastlog"
)

const (
	EthType8021AD = 0x88a8 // VLAN 802.1ad

	// Maximum ethernet II frame size is 1518 = 14 header + 1500 data + 8 802.ad (2x802.1Q tags)
	// see: https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
	EthMaxSize = 14 + 1500 + 8

	// Length of a link-layer address for Ethernet networks.
	EthAddrLen   = 6
	EthHeaderLen = 14
)

// EtherBufferPool implemts a simple buffer pool for Ethernet packets
var EtherBufferPool = sync.Pool{New: func() interface{} { return new([EthMaxSize]byte) }}

// ARP global variables
var (
	EthernetBroadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	EthernetZero      = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

// IsUnicastMAC return true if the mac address is unicast
//
// Bit 0 in the first octet is reserved for broadcast or multicast traffic.
// When we have unicast traffic this bit will be set to 0.
// For broadcast or multicast traffic this bit will be set to 1.
func IsUnicastMAC(mac net.HardwareAddr) bool {
	return mac[0]&0x01 == 0x00
}

// SrcMAC returns the src mac address from an ethernet packet.
// This is convenience function with just length validation.
func SrcMAC(b []byte) net.HardwareAddr {
	if len(b) >= 14 {
		return net.HardwareAddr(b[6 : 6+6])
	}
	return nil
}

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
	if len(p) >= EthHeaderLen {
		return nil
	}
	return fmt.Errorf("ethernet frame too short len=%d: %w", len(p), ErrFrameLen)
}

func (p Ether) Dst() net.HardwareAddr { return net.HardwareAddr(p[:6]) }
func (p Ether) Src() net.HardwareAddr { return net.HardwareAddr(p[6 : 6+6]) }
func (p Ether) EtherType() uint16     { return binary.BigEndian.Uint16(p[12:14]) } // same pos as PayloadLen

// SrcIP i a convenience function to return the source IP address. It returns nil if no IP packet is present.
func (p Ether) SrcIP() netip.Addr {
	switch p.EtherType() {
	case syscall.ETH_P_IP:
		return IP4(p.Payload()).Src()
	case syscall.ETH_P_IPV6:
		return IP6(p.Payload()).Src()
	}
	return netip.Addr{}
}

// SrcIP i a convenience function to return the destination IP address. It returns nil if no IP packet is present.
func (p Ether) DstIP() netip.Addr {
	switch p.EtherType() {
	case syscall.ETH_P_IP:
		return IP4(p.Payload()).Dst()
	case syscall.ETH_P_IPV6:
		return IP6(p.Payload()).Dst()
	}
	return netip.Addr{}
}

/**
// SrcIP i a convenience function to return the destination IP address in netip.Addr format. It returns nil if no IP packet is present.
func (p Ether) NetaddrDstIP() netip.Addr {
	if ip, ok := netip.AddrFromSlice(p.DstIP()); ok {
		return ip
	}
	return netip.Addr{}
}
*/

// HeaderLen returns the header length.
func (p Ether) HeaderLen() int {
	switch p.EtherType() {
	case syscall.ETH_P_IP, syscall.ETH_P_IPV6, syscall.ETH_P_ARP:
		return 14
	case syscall.ETH_P_8021Q:
		// The IEEE 802.1Q tag, if present, then two EtherType contains the Tag Protocol Identifier (TPID) value of 0x8100
		// and true EtherType/Length is located after the Q-tag.
		// The TPID is followed by two octets containing the Tag Control Information (TCI) (the IEEE 802.1p priority (quality of service) and VLAN id).
		// also handle 802.1ad - 0x88a8
		return 14 + 4 // add 4 bytes to frame
	case EthType8021AD:
		return 14 + 4 + 4 // add 8 bytes to frame (2x 802.1Q tags)
	}
	return 14
}

// Payload returns a slice to the payload after the header.
func (p Ether) Payload() []byte {
	n := p.HeaderLen()
	if len(p) > n {
		return p[n:]
	}
	if len(p) == n { // empty payload?
		return p[n:cap(p)] // return the full buffer - we are likely building a packet with marshall
	}
	return nil
}

// SetPayload extends the ether packet to include payload.
func (p Ether) SetPayload(payload []byte) (Ether, error) {
	tmp := p[:p.HeaderLen()+len(payload)]
	// An Ethernet frame has a minimum size of 60 bytes because anything that is shorter is interpreted
	// by receiving station as a frame resulting from a collision. This len was chosen to occupy the whole
	// distance of 1500 meters so the whole cable is occupied and collisions can be avoided.
	// pad smaller frames with zeros
	// see: https://serverfault.com/questions/510657/is-the-64-byte-minimal-ethernet-packet-rule-respected-in-practice

	// On Linux, padding is added automatically by the kernel driver.
	/*
		if n := len(tmp); n < 60 {
			tmp = tmp[:60]
			for n < 60 {
				tmp[n] = 0x00
				n++
			}
		}
	*/
	return tmp, nil
}

// AppendPayload copy payload after the ethernet header and returns the extended ether slice.
func (p Ether) AppendPayload(payload []byte) (Ether, error) {
	if len(payload)+14 > cap(p) { //must be enough capacity to store header + payload
		return nil, ErrPayloadTooBig
	}
	copy(p.Payload()[:cap(payload)], payload)

	// An Ethernet frame has a minimum size of 60 bytes because anything that is shorter is interpreted
	// by receiving station as a frame resulting from a collision. This len was chosen to occupy the whole
	// distance of 1500 meters so the whole cable is occupied and collisions can be avoided.
	// see: https://serverfault.com/questions/510657/is-the-64-byte-minimal-ethernet-packet-rule-respected-in-practice
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
	return Logger.Msg("").Struct(p).ToString()
}

// Fastlog implements fastlog struct interface
func (p Ether) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint16Hex("type", p.EtherType())
	line.MAC("src", p.Src())
	line.MAC("dst", p.Dst())
	line.Int("len", len(p))
	return line
}

// EncodeEther creates a ethernet frame at b using the parameters.
// It panic if b is nil or not sufficient to store a full len ethernet packet. In most cases this is a coding error.
func EncodeEther(b []byte, hType uint16, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr) Ether {
	if cap(b) < 14 {
		panic("ether buffer too small")
	}
	b = b[:14] // use only 14 bytes
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
	line := Logger.Msg("")
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
	return Logger.Msg("").Struct(p).ToString()
}

func (p EthernetPause) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint16Hex("opcode", p.Opcode())
	line.Uint16Hex("duration", p.Duration())
	return line
}

// LLDP provides access to Local Link Discovery Protocol
type LLDP []byte

func (p LLDP) IsValid() error {
	if len(p) < 6 {
		return ErrFrameLen
	}
	return nil
}

func (p LLDP) ChassisID() []byte {
	_, _, v, _ := p.getTLV(0)
	return v
}
func (p LLDP) PortID() []byte {
	c := p.ChassisID()
	_, _, v, _ := p.getTLV(len(c) + 2) // skip first PDU
	return v
}

func (p LLDP) GetPDU(pduType int) []byte {
	pos := 0
	for {
		t, l, v, err := p.getTLV(pos)
		if err != nil {
			return nil
		}
		if t == pduType || t == 0 { // return if end of TLV
			return v
		}
		pos = pos + l + 2
	}
}

func (p LLDP) getTLV(n int) (t int, l int, v []byte, err error) {
	if len(p) <= n+2 {
		return 0, 0, nil, ErrParseFrame
	}
	t = int(p[n] >> 1) // type = 7 bits
	l = (int(p[n]) & 0x01 << 8) + int(p[n+1])
	if t == 0 && l == 0 { // end of LLPDU
		return t, l, nil, nil
	}
	if len(p) > n+2+int(l)+2 {
		return t, l, p[n+2 : n+l], nil
	}
	return 0, 0, nil, ErrParseFrame
}

func (p LLDP) String() string {
	return Logger.Msg("").Struct(p).ToString()
}

func (p LLDP) Type(t int) string {
	switch t {
	case 0:
		return "endpdu"
	case 1:
		return "chassisID"
	case 2:
		return "port"
	case 3:
		return "ttl"
	case 4:
		return "portdesc"
	case 5:
		return "name"
	case 6:
		return "description"
	case 7:
		return "capabilities"
	case 8:
		return "mngntaddr"
	default:
		return strconv.Itoa(t)
	}
}

func (p LLDP) Capability(v []byte) string {
	if len(v) < 2 {
		return ""
	}
	// System capabilities TLV: Indicates the primary function(s) of the device and whether or not these
	// functions are enabled in the device. The capabilities are indicated by two octects.
	// Bits 0 through 7 indicate Other, Repeater, Bridge, WLAN AP, Router, Telephone, DOCSIS cable device and Station respectively. Bits 8 through 15 are reserved.
	s := ""
	if (v[1] & 0x80) == 0x80 {
		s = s + "other,"
	}
	if (v[1] & 0x40) == 0x40 {
		s = s + "repeater,"
	}
	if (v[1] & 0x20) == 0x20 {
		s = s + "bridge,"
	}
	if (v[1] & 0x10) == 0x10 {
		s = s + "AP,"
	}
	if (v[1] & 0x08) == 0x08 {
		s = s + "router,"
	}
	if (v[1] & 0x04) == 0x04 {
		s = s + "phone,"
	}
	if (v[1] & 0x02) == 0x02 {
		s = s + "docsis,"
	}
	if (v[1] & 0x01) == 0x01 {
		s = s + "station,"
	}
	if len(s) > 0 {
		return s[:len(s)-1]
	}
	return ""
}

func (p LLDP) FastLog(line *fastlog.Line) *fastlog.Line {
	pos := 0
	for {
		t, l, v, err := p.getTLV(pos)
		if err != nil {
			break
		}
		if t == 0 { // return if end of TLV
			break
		}
		switch t {
		case 5, 6:
			line.String(p.Type(t), string(v))
		case 7:
			line.ByteArray("capability", v)
			line.String("type", p.Capability(v))
		default:
			line.ByteArray(p.Type(t), v)
		}
		pos = pos + l + 2
	}
	return line
}

// unknown880a unkownn ether type 0x880a
type Unknown880a []byte

func (p Unknown880a) IsValid() error {
	if len(p) <= 0 {
		return ErrFrameLen
	}
	return nil
}
