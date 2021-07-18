package packet

import (
	"encoding/binary"
	"fmt"
)

// Local Link Control
type LLC []byte

func (p LLC) IsValid() error {
	if len(p) < 3 {
		return ErrFrameLen
	}
	return nil
}

func (p LLC) DSAP() uint8    { return p[0] }
func (p LLC) SSAP() uint8    { return p[1] }
func (p LLC) Control() uint8 { return p[2] }
func (p LLC) Type() string {
	// see https://diagnosticsoft.com/news/8022-frame-format-llc-53
	if p[2] == 0x03 && p[0] == 0xaa && p[1] == 0xaa {
		return "snap"
	}
	if p[2]&0x3 == 0x03 {
		return "u" // unnumbered frame format 8 bits
	}
	if p[2]&0x01 == 0x01 {
		return "s" // supervisory frame format 16 bits
	}
	return "i" // i-frame  format 16 bits
}
func (p LLC) Payload() []byte {
	if p.Type() == "u" {
		return p[3:]
	}
	return p[4:]
}

func (p LLC) String() string {
	return fmt.Sprintf("dsap=%x ssap=%x type=%s control1=%x", p.DSAP(), p.SSAP(), p.Type(), p.Control())
}

// Local Link Control - SNAP extension
//    +-------+--------+--------+
//    |  MAC Header    (14 bytes)                                802.{3/4/5} MAC
//    +--------+--------+--------+
//    | DSAP=AA| SSAP=AA| Control|                               802.2 LLC - unnumbered (1 byte control = 0x03)
//    +--------+--------+---------+--------+--------+
//    |    OUI                    |    EtherType    |            802.2 SNAP - OUI is zero if using EtheryType otherwise it is an organisation ID
//    +--------+--------+---------+--------+--------+
//    The total length of the LLC Header and the SNAP header is 8-octets.
//    An organizationally unique identifier (OUI) is a 24-bit number that uniquely identifies a vendor, manufacturer, or other organization.

type SNAP []byte

func (p SNAP) IsValid() error {
	if len(p) < 8+1 { // must have at least one byte in payload
		return ErrFrameLen
	}
	return nil
}

func (p SNAP) DSAP() uint8            { return p[0] }
func (p SNAP) SSAP() uint8            { return p[1] }
func (p SNAP) Control() uint8         { return p[2] }
func (p SNAP) OrganisationID() []byte { return p[3:6] }
func (p SNAP) EtherType() uint16      { return binary.BigEndian.Uint16(p[6:8]) }
func (p SNAP) Payload() []byte        { return p[8:] }
func (p SNAP) String() string {
	return fmt.Sprintf("dsap=0x%x orgid=0x%x type=0x%x", p.DSAP(), p.OrganisationID(), p.EtherType())
}
