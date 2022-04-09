package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"syscall"

	"github.com/irai/packet"
	"golang.org/x/net/dns/dnsmessage"
)

// nbns implemente Netbios name service as per rfc1002
// https://datatracker.ietf.org/doc/html/rfc1002
//
// An old protocol but still in use in Windows 10 and Home routers in 2021.
const (
	moduleNBNS = "nbns"

	netbiosMaxNameLen = 16

	// response flag: bit 15
	responseRequest = 0x00 << 15

	// Opcode: bits 11,12,13,14
	opcodeQuery = 0 << 11

	// NbnsFlags: bits 4, 5, 6, 7, 8, 9, 10
	nmflagsMASK                = 0x7f << 4
	nmflagsUnicast             = 0x00 << 4
	nmflagsBroadcast           = 0x01 << 4
	nmflagsRecursionAvailable  = 0x08 << 4
	nmflagsRecursionDesired    = 0x10 << 4
	nmflagsTruncated           = 0x20 << 4
	nmflagsAuthoritativeAnswer = 0x40 << 4

	rcodeOK = 0x0
	// NbnsQuestionType
	questionTypeGeneral    = 0x0020 //  NetBIOS general Name Service Resource Record
	questionTypeNodeStatus = 0x0021 // NBSTAT NetBIOS NODE STATUS Resource Record (See NODE STATUS REQUEST)

	// NbnsQuestionClass
	questionClassInternet = 0x0001
)

var sequence uint16 = 1 // incremented for every packet sent

// encodeNBNSName creates a 34 byte string = 1 char length + 32 char netbios name + 1 final length (0x00).
// Netbios names are 16 bytes long = 16 characters (two bytes per character)
func encodeNBNSName(name string) []byte {
	// Netbios name is limited to 16 characters long
	if len(name) > netbiosMaxNameLen {
		name = name[:netbiosMaxNameLen-1] // truncate if name too long
	}

	if len(name) < netbiosMaxNameLen {
		name = name + strings.Repeat(" ", netbiosMaxNameLen-len(name))
	}
	buffer := bytes.Buffer{}

	// Name len = 16 * 2 bytes format
	buffer.Write([]byte{netbiosMaxNameLen * 2})

	for i := range name {
		var store [2]byte
		store[0] = 'A' + (name[i] >> 4)
		store[1] = 'A' + (name[i] & 0x0f)
		buffer.Write(store[:])
	}

	// Final name - len 0x00 means no more names
	buffer.Write([]byte{0x00})

	if Debug {
		log.Printf("nbns encode netbios name=%s len=%v", buffer.String(), len(buffer.Bytes()))
	}

	return buffer.Bytes()
}

func decodeNBNSName(buf []byte) (n int, name string, err error) {
	// Get the first name.
	// tmp := make([]byte, netbiosMaxNameLen*2+2)
	// err = binary.Read(buf, binary.BigEndian, &tmp)
	if len(buf) < 32+1+1 { // at least 32b + 1 len + 1 zero
		return 0, "", packet.ErrInvalidLen
	}
	if buf[len(buf)-1] != 0x00 {
		return 0, "", packet.ErrParseFrame
	}

	// A label length count is actually a 6-bit field in the label length
	// field.  The most significant 2 bits of the field, bits 7 and 6, are
	// flags allowing an escape from the above compressed representation.
	// Note that the first octet of a compressed name must contain one of
	// the following bit patterns.  (An "x" indicates a bit whose value may
	// be either 0 or 1.):
	//
	//    00100000 -  Netbios name, length must be 32 (decimal) (0x20)
	//    11xxxxxx -  Label string pointer
	//    10xxxxxx -  Reserved
	//    01xxxxxx -  Reserved
	if buf[0] != 0x20 {
		return 0, "", packet.ErrParseFrame
	}

	// we only care about the 16 bytes compressed name (ie. 32 bytes)
	// ignore scope id (i.e. anything after 16 bytes)
	buf = buf[1:] // 0 is len; name starts at 1
	for i := 0; i < 32; i = i + 2 {
		character := ((buf[i] - 'A') << 4) | (buf[i+1] - 'A')
		name = name + string(character)
	}

	return len(buf), strings.TrimRight(name, " "), nil
}

// SendNBNSQuery send NBNS node status request query
//
// nbnb query request is a standard dns question packet
// with class set to 0x20 (NBNS query request).
func (h *DNSHandler) SendNBNSQuery(srcAddr packet.Addr, dstAddr packet.Addr, name string) (err error) {
	const word = uint16(responseRequest | opcodeQuery | nmflagsUnicast | rcodeOK)
	sequence++
	p := dnsQueryMarshal(sequence, word, encodeNBNSName(name), questionTypeGeneral)
	return h.sendNBNS(srcAddr, dstAddr, p)
}

// SendNBNSNodeStatus transmit a nbns node status request.
//
// node status request is a standard dns question packet
// with class set to 0x21 (NBNS node status request).
func (h *DNSHandler) SendNBNSNodeStatus() (err error) {
	const name = `*               `
	const word = uint16(responseRequest | opcodeQuery | nmflagsUnicast | rcodeOK)
	sequence++
	p := dnsQueryMarshal(sequence, word, encodeNBNSName(name), questionTypeNodeStatus)
	return h.sendNBNS(h.session.NICInfo.HostAddr4, packet.IP4BroadcastAddr, p)
}

func (h *DNSHandler) sendNBNS(srcAddr packet.Addr, dstAddr packet.Addr, p DNS) (err error) {
	b := packet.EtherBufferPool.Get().(*[packet.EthMaxSize]byte)
	defer packet.EtherBufferPool.Put(b)
	ether := packet.Ether(b[0:])
	ether = packet.EncodeEther(ether, syscall.ETH_P_IP, srcAddr.MAC, dstAddr.MAC)
	ip4 := packet.EncodeIP4(ether.Payload(), 255, srcAddr.IP, dstAddr.IP)
	udp := packet.EncodeUDP(ip4.Payload(), 137, 137)
	if udp, err = udp.AppendPayload(p); err != nil {
		return err
	}
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)
	if ether, err = ether.SetPayload(ip4); err != nil {
		return err
	}
	if _, err := h.session.Conn.WriteTo(ether, &dstAddr); err != nil {
		return err
	}
	return nil
}

// parseNodeNameArray process a name arra in the status node response packet
//
// The first byte is the number of entries followed by an array of
//   name (16 bytes)
//   flags (2 bytes)
//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//      | G |     not important for our needs                           |
//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//      G               0   Group Name Flag.  If one (1) then the name is a GROUP NetBIOS name.  If zero (0) then it is a UNIQUE NetBIOS name.
//
// for full details refer to:
func parseNodeNameArray(b []byte) (names []string, err error) {
	if len(b) < 1 {
		return names, packet.ErrFrameLen
	}
	n := int(b[0])
	b = b[1:] // skip len byte
	if len(b) < n*16+2 {
		return names, packet.ErrFrameLen
	}
	for i := 0; i < n; i++ {
		index := 18 * i
		flags := binary.BigEndian.Uint16(b[index+16 : index+18]) // nameFlags
		if (flags & 0x8000) == 0x00 {                            // don't add to the table if this is group name
			nn := bytes.TrimRight(b[0:16], "\x00")
			nn = bytes.TrimRight(nn, " ")
			name := string(nn)
			names = append(names, string(name))
		}
	}
	return names, nil
}

// parseNodeStatusResponse
// 4.2.18.  NODE STATUS RESPONSE
//                           1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Header                                                |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   /                            RR_NAME (variable len)             /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        NBSTAT (0x0021)        |         IN (0x0001)           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                          0x00000000                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          RDLENGTH             |   NUM_NAMES   |               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
//   /                         NODE_NAME ARRAY  (variable len)       /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   /                           STATISTICS      (variable len)      /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func processNBNSNodeStatusResponse(b []byte) (names []string, err error) {
	if len(b) < 3 {
		return names, packet.ErrInvalidLen
	}
	// interested in names only
	names, err = parseNodeNameArray(b)
	// ignore statistics
	return names, err
}

func (h *DNSHandler) ProcessNBNS(host *packet.Host, ether packet.Ether, payload []byte) (name packet.NameEntry, err error) {
	dns := DNS(payload)
	if err := dns.IsValid(); err != nil {
		return name, err
	}
	if Debug {
		Logger.Msg("new nbns packet").Stringer(host).Struct(dns).Write()
	}
	var p dnsmessage.Parser
	dnsHeader, err := p.Start(payload)
	if err != nil {
		return name, err
	}
	if !dnsHeader.Response {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return name, err
	}

	name.Type = moduleNBNS

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return name, err
		}

		switch h.Type {
		case 0x20:
			fmt.Println("nbns unexpected name answer", h.Type)

		case 0x21:
			r, err := p.UnknownResource()
			if err != nil {
				return name, err
			}
			table, err := processNBNSNodeStatusResponse(r.Data)
			if err == nil && len(table) > 0 {
				name.Name = table[0]
				Logger.Msg("nbns new entry").String("name", name.Name).Write()
				return name, nil
			}
		default:
			/*
				if err := p.SkipAnswer(); err != nil {
					panic(err)
				}
			*/
			fmt.Println("nbns : ignoring invalid header type", h.Type)
		}
	}

	return name, nil
}
