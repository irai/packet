package packet

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/irai/packet/fastlog"
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
	// return fmt.Sprintf("dsap=%x ssap=%x type=%s control1=%x", p.DSAP(), p.SSAP(), p.Type(), p.Control())
	line := fastlog.NewLine("", "")
	return p.FastLog(line).ToString()
}

func (p LLC) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint8("dsap", p.DSAP())
	line.Uint8("ssap", p.SSAP())
	line.String("type", p.Type())
	line.Uint8("control", p.Control())
	return line
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
//    EtherType is zero if not carrying an registered EtherType
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
	// return fmt.Sprintf("dsap=0x%x control=0x%x orgid=0x%x ethertype=0x%x", p.DSAP(), p.Control(), p.OrganisationID(), p.EtherType())
	line := fastlog.NewLine("", "")
	return p.FastLog(line).ToString()
}

func (p SNAP) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint8("dsap", p.DSAP())
	line.Uint8("control", p.Control())
	line.ByteArray("orgid", p.OrganisationID())
	line.Uint16("ethertype", p.EtherType())
	return line
}

var stpCount int
var stpNextLog time.Time

// process8023Frame handle general layer 2 packets in Ethernet 802.3 format.
//
// see https://macaddress.io/faq/how-to-recognise-an-ieee-802-1x-mac-address-application
// see https://networkengineering.stackexchange.com/questions/64757/unknown-ethertype
// see https://www.mit.edu/~map/Ethernet/multicast.html
func Process8023Frame(frame Frame, pos int) (int, int, error) {
	llc := LLC(frame.Payload())
	if err := llc.IsValid(); err != nil {
		fmt.Printf("packet: err invalid LLC err=%s\n", err)
		return 0, 0, err
	}

	// SONOS - LLC, dsap STP (0x42) Individual, ssap STP (0x42) Command
	// uses "01:80:c2:00:00:00" destination MAC
	// http://www.netrounds.com/wp-content/uploads/public/layer-2-control-protocol-handling.pdf
	// https://techhub.hpe.com/eginfolib/networking/docs/switches/5980/5200-3921_l2-lan_cg/content/499036672.htm#:~:text=STP%20protocol%20frames%20STP%20uses%20bridge%20protocol%20data,devices%20exchange%20BPDUs%20to%20establish%20a%20spanning%20tree.
	if llc.DSAP() == 0x42 && llc.SSAP() == 0x42 {
		stpCount++
		now := time.Now()
		if stpNextLog.Before(now) {
			fastlog.NewLine(module, "LLC STP protocol").Struct(frame.Ether).Struct(llc).Int("count", stpCount).ByteArray("payload", frame.Ether.Payload()).Write()
			stpNextLog = now.Add(time.Minute * 5)
		}
		return 0, 0, nil
	}

	if llc.DSAP() == 0xaa && llc.SSAP() == 0xaa && llc.Control() == 0x03 {
		snap := SNAP(llc)
		if err := snap.IsValid(); err != nil {
			fmt.Printf("packet: err invalid SNAP packet err=%s\n", err)
			return 0, 0, err
		}
		// fmt.Printf("packet: LLC SNAP protocol %s %s payload=[% x]\n", ether, snap, ether[:])
		fastlog.NewLine(module, "LLC SNAP protocol").Struct(frame.Ether).Struct(snap).ByteArray("payload", frame.Ether.Payload()).Write()
		return 0, 0, nil
	}

	if llc.DSAP() == 0xe0 && llc.SSAP() == 0xe0 {
		fastlog.NewLine(module, "IPX protocol").Struct(frame.Ether).ByteArray("payload", frame.Ether.Payload()).Write()
		return 0, 0, nil
	}

	// wifi mac notification -
	// To see these:
	//    sudo tcpdump -vv -x not ip6 and not ip and not arp
	//    then switch a mobile phone to airplane mode to force a network reconnect
	// fmt.Printf("packet: rcvd 802.3 LLC frame %s %s payload=[% x]\n", ether, llc, ether[:])
	fastlog.NewLine(module, "802.3 LLC frame").Struct(frame.Ether).ByteArray("payload", frame.Ether.Payload()).Write()
	return 0, 0, nil
}
