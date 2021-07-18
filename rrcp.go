package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// TODO: finish and test this
// Realtek Remote Control Protocol
// Proprietary protocol from Realtek with few details available on the net
//
// comments from Linus Walleij on the Linux Distributet Switch Architecture kernel discussion group
//     It's actually quite annoying, Realtek use type 0x8899 for all their
//     custom stuff, including RRCP and internal DSA(distributed switch architecture in the Linux kernel) tagging inside
//     switches, which are two completely different use cases.
//
//     When I expose raw DSA frames to wireshark it identifies it
//     as "Realtek RRCP" and then naturally cannot decode the
//     frames since this is not RRCP but another protocol identified
//     by the same ethertype.
//
// There are at least four protocols out there using ethertype 0x8899.
//    0x01 - RRCP
//    0x23 - loop detection
//    0x9x - DSA
//    0xax - DSA
//
// RRCP protocol description: http://realtek.info/pdf/rtl8324.pdf
//                            http://openrrcp.org.ru/download/datasheets/RTL8326_8326S_DataSheet_3.1.pdf
// some sample C code here: https://www.wireshark.org/lists/ethereal-dev/200409/msg00090.html
//                          https://github.com/the-tcpdump-group/tcpdump/blob/master/print-rrcp.c
// see discussion here:
// https://lore.kernel.org/netdev/20210217122508.y4rjhjjqn4kyc7mq@skbuf/t/
//
// + * This tag header looks like:
// + *
// + * -------------------------------------------------
// + * | MAC DA | MAC SA | 0x8899 | 2-byte tag  | Type |
// + * -------------------------------------------------
// + *
// + * The 2-byte tag format in tag_rcv:
// + *       +------+------+------+------+------+------+------+------+
// + * 15: 8 |   Protocol number (0x9)   |  Priority   |  Reserved   |
// + *       +------+------+------+------+------+------+------+------+
// + *  7: 0 |             Reserved             | Source port number |
// + *       +------+------+------+------+------+------+------+------+
// + *
// + * The 2-byte tag format in tag_xmit:
// + *       +------+------+------+------+------+------+------+------+
// + * 15: 8 |   Protocol number (0x9)   |  Priority   |  Reserved   |
// + *       +------+------+------+------+------+------+------+------+
// + *  7: 0 |  Reserved   |          Destination port mask          |
// + *       +------+------+------+------+------+------+------+------+
type RRCP []byte

func (p RRCP) IsValid() error {
	// Minimum len to contain two hardware address and EtherType (2 bytes)
	if len(p) >= 21 {
		return nil
	}
	return ErrFrameLen
}

// 0x23 - Loop detection - RTL8305
//        supposely 64 bytes long (inc ether 14) but we are seeing 60 bytes on Arris router
//
// see - https://www.openhacks.com/uploadsproductos/realtek-semicon-rtl8305nb-cg-qfn-48_c52146.pdf
//                  1byte                         1byte
// + *       +---------------------------+---------------------------+
// + *       |              Protocol number - 0x2300                 |
// + *       +-------------------------------------------------------+
// + *       |    12bits - 0x000                   | 4bits  TTL      |
// + *       +-------------------------------------------------------+
// + *       |    352 bits        0x00                               |
// + *       +-------------------------------------------------------+

func (p RRCP) Dst() net.HardwareAddr { return net.HardwareAddr(p[:6]) }
func (p RRCP) Src() net.HardwareAddr { return net.HardwareAddr(p[6 : 6+6]) }
func (p RRCP) EtherType() uint16     { return binary.BigEndian.Uint16(p[12:14]) }
func (p RRCP) Protocol() byte        { return p[14] }                             // 8bits - 0x01 Realtek Remote Control Protocol; 0x23 Loop detection
func (p RRCP) Reply() bool           { return (p[15]&0x80 == 0x80) }              // 1 bit - 1 reply from switch to management station
func (p RRCP) OpCode() byte          { return p[15] & 0x7f }                      // 7 bits - 00 Hello; 01 Get configuration; 02 Set configuration
func (p RRCP) AuthKey() uint16       { return binary.BigEndian.Uint16(p[15:17]) } // Authentication key - default 0x2379
func (p RRCP) RegisterAddr() uint16  { return binary.BigEndian.Uint16(p[17:19]) } // register addr
func (p RRCP) RegisterData() uint16  { return binary.BigEndian.Uint16(p[19:21]) } // register data

func (p RRCP) String() string {
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
	b.WriteString(" protocol=0x")
	fmt.Fprintf(&b, "%x", p.Protocol())
	b.WriteString(" reply=")
	fmt.Fprintf(&b, "%v", p.Reply())
	b.WriteString(" opcode=0x")
	fmt.Fprintf(&b, "%x", p.OpCode())
	return b.String()
}
