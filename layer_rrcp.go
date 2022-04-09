package packet

import (
	"encoding/binary"

	"github.com/irai/packet/fastlog"
)

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

type RRCP []byte

func (p RRCP) IsValid() error {
	if len(p) < 16 { // minimum to prevent segfault; in reality all packets are at least 60 bytes long. in reality packets will be >= 60
		return ErrFrameLen
	}
	return nil
}

// Protocol 0x01 - the original format but not seen in logs yet.
//      RRCP protocol description: http://realtek.info/pdf/rtl8324.pdf
//                                 http://openrrcp.org.ru/download/datasheets/RTL8326_8326S_DataSheet_3.1.pdf
//      some sample C code here: https://www.wireshark.org/lists/ethereal-dev/200409/msg00090.html
//                               https://github.com/the-tcpdump-group/tcpdump/blob/master/print-rrcp.c
func (p RRCP) Protocol() uint8      { return p[0] }                            // 8bits - 0x01 Realtek Remote Control Protocol; 0x23 Loop detection
func (p RRCP) Reply() bool          { return (p[1]&0x80 == 0x80) }             // 1 bit - 1 reply from switch to management station
func (p RRCP) OpCode() uint8        { return p[1] & 0x7f }                     // 7 bits - 00 Hello; 01 Get configuration; 02 Set configuration
func (p RRCP) AuthKey() uint16      { return binary.BigEndian.Uint16(p[2:4]) } // Authentication key - default 0x2379
func (p RRCP) RegisterAddr() uint16 { return binary.BigEndian.Uint16(p[4:6]) } // register addr
func (p RRCP) RegisterData() uint16 { return binary.BigEndian.Uint16(p[6:8]) } // register data

func (p RRCP) String() string {
	return Logger.Msg("").Struct(p).ToString()
}

func (p RRCP) FastLog(l *fastlog.Line) *fastlog.Line {
	switch p.Protocol() {
	case 0x23:
		l.String("protocol", "realtek loop detection (0x23)")
		l.ByteArray("sixbytes", p.SixBytes())
		l.ByteArray("zeros", p.Zeros())
	case 0x01:
		l.String("protocol", "realtek (0x01)")
		l.Bool("reply", p.Reply())
		l.Uint8Hex("opcode", p.OpCode())
	default:
		l.Uint8Hex("protocol", p.Protocol())
		l.String("msg", "unknown realtek protocol")
		l.ByteArray("payload", p)
	}
	return l
}

// Protocol 0x23 - Loop detection - RTL8305
//        common in Arris router
//        see - https://www.openhacks.com/uploadsproductos/realtek-semicon-rtl8305nb-cg-qfn-48_c52146.pdf
//                  1byte                         1byte
// + *       +---------------------------+---------------------------+
// + *       |              Protocol number - 0x2300                 |
// + *       +-------------------------------------------------------+
// + *       |    12bits - 0x000                   | 4bits  TTL      |
// + *       +-------------------------------------------------------+
// + *       |    352 bits        0x00                               |
// + *       +-------------------------------------------------------+
func (p RRCP) SixBytes() []byte { return p[1 : 1+6] } // not sure what this is; it does not match the description in rtl8305
func (p RRCP) Zeros() []byte    { return p[7:] }      // not sure what this is; it does not match the description in rtl8305

// Protocol 0x9x - DSA
//        we have not seen this proto yet
//        see discussion here:
//        https://lore.kernel.org/netdev/20210217122508.y4rjhjjqn4kyc7mq@skbuf/t/
//
// + * This tag header looks like:
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
