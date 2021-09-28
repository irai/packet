package packet

import (
	"encoding/binary"

	"github.com/irai/packet/fastlog"
)

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
