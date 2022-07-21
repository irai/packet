package packet

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"

	"github.com/irai/packet/fastlog"
)

// ARP Operation types
const (
	ARPOperationRequest = 1
	ARPOperationReply   = 2
)

// ARP provides access to ARP fields without copying the structure.
type ARP []byte

// ARPLen length is header + 2 * MACs + 2 IPs
// in theory MAC and IP len can vary
const ARPLen = 8 + 2*6 + 2*4

func (b ARP) IsValid() error {
	if len(b) < ARPLen {
		return ErrFrameLen
	}
	if b.HType() != 1 {
		return ErrParseFrame
	}
	if b.Proto() != syscall.ETH_P_IP {
		return ErrParseProtocol
	}
	if b.HLen() != 6 {
		return ErrInvalidLen
	}
	if b.PLen() != 4 {
		return ErrInvalidLen
	}

	return nil
}

func (b ARP) HType() uint16            { return binary.BigEndian.Uint16(b[0:2]) }
func (b ARP) Proto() uint16            { return binary.BigEndian.Uint16(b[2:4]) }
func (b ARP) HLen() uint8              { return b[4] }
func (b ARP) PLen() uint8              { return b[5] }
func (b ARP) Operation() uint16        { return binary.BigEndian.Uint16(b[6:8]) }
func (b ARP) SrcMAC() net.HardwareAddr { return net.HardwareAddr(b[8:14]) }
func (b ARP) SrcIP() netip.Addr        { return netip.AddrFrom4(*(*[4]byte)(b[14:18])) }
func (b ARP) DstMAC() net.HardwareAddr { return net.HardwareAddr(b[18:24]) }
func (b ARP) DstIP() netip.Addr        { return netip.AddrFrom4(*(*[4]byte)(b[24:28])) }
func (b ARP) String() string           { return Logger.Msg("").Struct(b).ToString() }

func (b ARP) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint16("operation", b.Operation())
	line.MAC("srcMAC", b.SrcMAC())
	line.IP("srcIP", b.SrcIP())
	line.MAC("dstMAC", b.DstMAC())
	line.IP("dstIP", b.DstIP())
	return line
}

// EncodeARP creates a wire ARP frame ready for transmission
// see format: https://en.wikipedia.org/wiki/Address_Resolution_Protocol
func EncodeARP(b []byte, operation uint16, srcAddr Addr, dstAddr Addr) ARP {
	if cap(b) < ARPLen {
		panic("invalid arp buffer")
	}
	b = b[:ARPLen] // change the slice to accomodate the index below in case slice is less than arpLen

	binary.BigEndian.PutUint16(b[0:2], 1)                // Hardware Type - Ethernet is 1
	binary.BigEndian.PutUint16(b[2:4], syscall.ETH_P_IP) // Protocol type - IPv4 0x0800
	b[4] = 6                                             // mac len - fixed
	b[5] = 4                                             // ipv4 len - fixed
	binary.BigEndian.PutUint16(b[6:8], operation)        // operation - 1 request, 2 reply
	copy(b[8:8+6], srcAddr.MAC[:6])
	copy(b[14:14+4], srcAddr.IP.AsSlice())
	copy(b[18:18+6], dstAddr.MAC[:6])
	copy(b[24:24+4], dstAddr.IP.AsSlice())
	return b
}
