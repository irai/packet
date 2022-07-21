package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/irai/packet/fastlog"
)

// NbnsQuestionClass
const questionClassInternet = 0x0001

// DNS represents a DNS packet as specified in RFC 1034 / RFC 1035
// see : https://github.com/google/gopacket/blob/master/layers/dns.go
//
//  DNS packet format
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      ID                       |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    QDCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ANCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    NSCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ARCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type DNS []byte

func (p DNS) IsValid() error {
	if len(p) >= 12 {
		return nil
	}
	return ErrFrameLen
}

func (p DNS) String() string {
	return fmt.Sprintf("qr=%v tc=%v rcode=%v qdcount=%d ancount=%d nscount=%d arcount=%d", p.QR(), p.TC(), p.ResponseCode(), p.QDCount(), p.ANCount(), p.NSCount(), p.ARCount())
}

func (p DNS) FastLog(l *fastlog.Line) *fastlog.Line {
	l.Uint16("tranid", p.TransactionID())
	l.Bool("qr", p.QR())
	l.Bool("rc", p.TC())
	l.Int("rcode", p.ResponseCode())
	l.Uint16("qdcount", p.QDCount())
	l.Uint16("ancount", p.ANCount())
	l.Uint16("nscount", p.NSCount())
	l.Uint16("arcount", p.ARCount())
	return l
}

func (p DNS) TransactionID() uint16 { return binary.BigEndian.Uint16(p[:2]) }
func (p DNS) QR() bool              { return p[2]&0x80 != 0 }                    // 1 - query ; 0 - response
func (p DNS) OpCode() int           { return int(p[2]>>3) & 0x0F }               // OpCode
func (p DNS) AA() bool              { return p[2]&0x04 != 0 }                    // authoritative answer
func (p DNS) TC() bool              { return p[2]&0x02 != 0 }                    // Truncated answer - true if answer is longer than 512 bytes
func (p DNS) RD() bool              { return p[2]&0x01 != 0 }                    // recursion desired
func (p DNS) RA() bool              { return p[3]&0x80 != 0 }                    // recursion available
func (p DNS) Z() uint8              { return uint8(p[3]>>4) & 0x07 }             // zero
func (p DNS) ResponseCode() int     { return int(p[3]) & 0x0F }                  // response code
func (p DNS) QDCount() uint16       { return binary.BigEndian.Uint16(p[4:6]) }   // query count
func (p DNS) ANCount() uint16       { return binary.BigEndian.Uint16(p[6:8]) }   // answer count
func (p DNS) NSCount() uint16       { return binary.BigEndian.Uint16(p[8:10]) }  // Authority record count
func (p DNS) ARCount() uint16       { return binary.BigEndian.Uint16(p[10:12]) } // Additional information count

func EncodeDNSQuery(tranID uint16, flags uint16, encodedName []byte, questionType uint16) DNS {
	b := make([]byte, 512)
	binary.BigEndian.PutUint16(b[0:2], tranID)
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint16(b[4:6], 1)   // QDcount
	binary.BigEndian.PutUint16(b[6:8], 0)   // ANCount
	binary.BigEndian.PutUint16(b[8:10], 0)  // NScount
	binary.BigEndian.PutUint16(b[10:12], 0) // ARcount
	n := copy(b[12:], []byte(encodedName))
	binary.BigEndian.PutUint16(b[12+n:], questionType)
	binary.BigEndian.PutUint16(b[14+n:], questionClassInternet)
	return b[:16+n]
}

type Question struct {
	Name  []byte
	Type  uint16
	Class uint16
}

// DecodeQuestion returns the first question in the DNS packet
func DecodeQuestion(p DNS, index int, buffer []byte) (question Question, off int, err error) {
	if p.QDCount() != 1 { // assume a single question
		return Question{}, -1, ErrParseFrame
	}

	// get first answer
	if index+6 > len(p) { // must have at least 2 bytes name, 4 bytes type and class
		return Question{}, -1, ErrParseFrame
	}
	name, endq, err := decodeName(p, index, &buffer, 1)
	if err != nil {
		return Question{}, -1, err
	}

	question.Name = name
	question.Type = binary.BigEndian.Uint16(p[endq : endq+2])    // 2 bytes
	question.Class = binary.BigEndian.Uint16(p[endq+2 : endq+4]) // 2 bytes
	index = endq + 4                                             // 4 bytes type and class

	return question, index, nil
}

type NameResourceRecord struct {
	Name  string
	CName string
	TTL   uint32
}

type IPResourceRecord struct {
	Name string
	IP   netip.Addr
	TTL  uint32
}

type DNSEntry struct {
	Name         string
	IP4Records   map[netip.Addr]IPResourceRecord
	IP6Records   map[netip.Addr]IPResourceRecord
	CNameRecords map[string]NameResourceRecord
	PTRRecords   map[string]IPResourceRecord
}

func NewDNSEntry() (entry DNSEntry) {
	entry.IP4Records = make(map[netip.Addr]IPResourceRecord)
	entry.IP6Records = make(map[netip.Addr]IPResourceRecord)
	entry.CNameRecords = make(map[string]NameResourceRecord)
	entry.PTRRecords = make(map[string]IPResourceRecord)
	return entry
}

// decode decodes the resource record, returning the total length of the record.
//
// not goroutine safe:
//   must acquire lock before calling as function will update maps
func (e *DNSEntry) DecodeAnswers(p DNS, offset int, buffer []byte) (int, bool, error) {
	return e.decodeRRs(int(p.ANCount()), p, offset, buffer)
}

// decodeRRs decodes resource records returning the total length of the record.
//  DNSResourceRecord
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                                               |
//  /                                               /
//  /                      NAME                     /
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      TYPE                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                     CLASS                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      TTL                      |
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   RDLENGTH                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//  /                     RDATA                     /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
func (e *DNSEntry) decodeRRs(count int, p DNS, offset int, buffer []byte) (int, bool, error) {
	var updated bool
	var tmpBuf []byte // temporary buffer to avoid allocation
	for i := 0; i < count; i++ {
		tmpBuf = buffer
		name, endq, err := decodeName(p, offset, &tmpBuf, 1)
		if err != nil {
			return 0, false, fmt.Errorf("invalid label: %w", err)
		}

		t := binary.BigEndian.Uint16(p[endq : endq+2]) // type
		// class = binary.BigEndian.Uint16(p[endq+2 : endq+4])
		ttl := binary.BigEndian.Uint32(p[endq+4 : endq+8]) // number of seconds the RR can be cached
		dataLen := binary.BigEndian.Uint16(p[endq+8 : endq+10])
		offset = endq + 10 + int(dataLen)
		if offset > len(p) {
			return 0, false, fmt.Errorf("invalid resource record len: %w", ErrInvalidLen)
		}

		switch t {
		case 1: // A
			if dataLen != 4 {
				return 0, false, fmt.Errorf("invalid A data len: %w", ErrInvalidLen)
			}
			ip, _ := netip.AddrFromSlice(net.IP(p[endq+10 : endq+10+4]))
			if _, found := e.IP4Records[ip]; !found {
				e.IP4Records[ip] = IPResourceRecord{Name: string(name), IP: ip, TTL: ttl}
				updated = true
			}

		case 28: // AAAA
			if dataLen != 16 {
				return 0, false, fmt.Errorf("invalid AAAA data len: %w", ErrInvalidLen)
			}
			ip, _ := netip.AddrFromSlice(net.IP(p[endq+10 : endq+10+16]))
			if _, found := e.IP6Records[ip]; !found {
				e.IP6Records[ip] = IPResourceRecord{Name: string(name), IP: ip, TTL: ttl}
				updated = true
			}

		case 5: // CNAME
			var cname []byte
			tmpBuf = buffer
			cname, _, err = decodeName(p, endq+10, &tmpBuf, 1)
			if err != nil {
				return 0, false, fmt.Errorf("invalid CNAME data: %w", err)
			}
			if _, found := e.CNameRecords[string(name)]; !found {
				r := NameResourceRecord{Name: string(name), TTL: ttl, CName: string(cname)}
				e.CNameRecords[r.Name] = r
				updated = true
			}

		case 15: // MX record
			if Logger.IsDebug() {
				fmt.Println("dns   : received MX record response - ignoring", string(name))
			}

		case 12: // PTR record
			s := strings.TrimSuffix(string(name), ".in-addr.arpa")
			tmp := net.ParseIP(s)
			if tmp == nil {
				return 0, false, fmt.Errorf("invalid PTR IP: %s", string(name))
			}
			if tmp = tmp.To4(); tmp == nil {
				fmt.Printf("dns   : ignoring ptr ip6=%s\n", tmp)
				break
			}
			ip, _ := netip.AddrFromSlice([]byte{tmp[3], tmp[2], tmp[1], tmp[0]})
			var ptr []byte
			tmpBuf = buffer
			ptr, _, err = decodeName(p, endq+10, &tmpBuf, 1)
			if err != nil {
				return 0, false, fmt.Errorf("invalid PTR data: %w", err)
			}
			r := IPResourceRecord{Name: string(ptr), TTL: ttl, IP: ip}
			if _, found := e.PTRRecords[r.Name]; !found {
				e.PTRRecords[r.Name] = r
				updated = true
			}
			if Logger.IsDebug() {
				fmt.Printf("dns   : received PTR record response ptr=%s ip=%s\n", r.Name, r.IP)
			}
		default:
			fmt.Println("dns   : unexpected dns resource record ", t, string(name))
		}
	}

	return offset, updated, nil
}

// copy returns a deep copy of DNSEntry
func (d DNSEntry) Copy() DNSEntry {
	e := DNSEntry{Name: d.Name}
	e.IP4Records = make(map[netip.Addr]IPResourceRecord, len(d.IP4Records))
	e.IP6Records = make(map[netip.Addr]IPResourceRecord, len(d.IP6Records))
	e.CNameRecords = make(map[string]NameResourceRecord, len(d.CNameRecords))
	e.PTRRecords = make(map[string]IPResourceRecord, len(d.PTRRecords))
	for k, v := range d.IP4Records {
		e.IP4Records[k] = v
	}
	for k, v := range d.IP6Records {
		e.IP6Records[k] = v
	}
	for k, v := range d.CNameRecords {
		e.CNameRecords[k] = v
	}
	for k, v := range d.PTRRecords {
		e.PTRRecords[k] = v
	}
	return e
}

func (d DNSEntry) IP4List() []netip.Addr {
	list := make([]netip.Addr, 0, len(d.IP4Records))
	for _, v := range d.IP4Records {
		list = append(list, v.IP)
	}
	return list
}

func (d DNSEntry) IP6List() []netip.Addr {
	list := make([]netip.Addr, 0, len(d.IP6Records))
	for _, v := range d.IP6Records {
		list = append(list, v.IP)
	}
	return list
}

func (d DNSEntry) CNameList() []string {
	list := make([]string, 0, len(d.CNameRecords))
	for _, v := range d.CNameRecords {
		list = append(list, v.CName)
	}
	return list
}

func (d DNSEntry) FastLog(l *fastlog.Line) *fastlog.Line {
	l.String("name", d.Name)
	str := make([]string, 0, 16)
	for _, v := range d.IP4Records {
		str = append(str, v.IP.String())
	}
	l.StringArray("ip4", str)
	str = str[:0]
	for _, v := range d.IP6Records {
		str = append(str, v.IP.String())
	}
	l.StringArray("ip6", str)
	str = str[:0]
	for _, v := range d.CNameRecords {
		str = append(str, v.CName)
	}
	l.StringArray("cname", str)
	return l

}

// NameEntry holds a name entry
type DNSNameEntry struct {
	Addr         Addr
	Name         string
	Model        string
	Manufacturer string
	OS           string
}

func (n DNSNameEntry) FastLog(l *fastlog.Line) *fastlog.Line {
	l.Struct(n.Addr)
	l.String("name", n.Name)
	l.String("model", n.Model)
	return l
}

func encode(qType uint16, qClass uint16, qName []byte, data []byte, offset int) int {
	noff := encodeName(qName, data, offset)
	nSz := noff - offset
	binary.BigEndian.PutUint16(data[noff:], uint16(qType))
	binary.BigEndian.PutUint16(data[noff+2:], uint16(qClass))
	return nSz + 4
}

// encodeName extracted from https://github.com/google/gopacket/blob/master/layers/dns.go
func encodeName(name []byte, data []byte, offset int) int {
	l := 0
	for i := range name {
		if name[i] == '.' {
			data[offset+i-l] = byte(l)
			l = 0
		} else {
			// skip one to write the length
			data[offset+i+1] = name[i]
			l++
		}
	}

	if len(name) == 0 {
		data[offset] = 0x00 // terminal
		return offset + 1
	}

	// length for final portion
	data[offset+len(name)-l] = byte(l)
	data[offset+len(name)+1] = 0x00 // terminal
	return offset + len(name) + 2
}

const maxRecursionLevel = 255

// decodeName extracted from https://github.com/google/gopacket/blob/master/layers/dns.go
func decodeName(data []byte, offset int, buffer *[]byte, level int) ([]byte, int, error) {
	if level > maxRecursionLevel {
		return nil, 0, ErrParseFrame
	} else if offset >= len(data) {
		return nil, 0, ErrParseFrame
	} else if offset < 0 {
		return nil, 0, ErrParseFrame
	}
	start := len(*buffer)
	index := offset
	if data[index] == 0x00 {
		return nil, index + 1, nil
	}
loop:
	for data[index] != 0x00 {
		switch data[index] & 0xc0 {
		default:
			/* RFC 1035
			   A domain name represented as a sequence of labels, where
			   each label consists of a length octet followed by that
			   number of octets.  The domain name terminates with the
			   zero length octet for the null label of the root.  Note
			   that this field may be an odd number of octets; no
			   padding is used.
			*/
			index2 := index + int(data[index]) + 1
			if index2-offset > 255 {
				return nil, 0, ErrParseFrame
			} else if index2 < index+1 || index2 > len(data) {
				return nil, 0, ErrParseFrame
			}
			*buffer = append(*buffer, '.')
			*buffer = append(*buffer, data[index+1:index2]...)
			index = index2

		case 0xc0:
			/* RFC 1035
			   The pointer takes the form of a two octet sequence.
			   The first two bits are ones.  This allows a pointer to
			   be distinguished from a label, since the label must
			   begin with two zero bits because labels are restricted
			   to 63 octets or less.  (The 10 and 01 combinations are
			   reserved for future use.)  The OFFSET field specifies
			   an offset from the start of the message (i.e., the
			   first octet of the ID field in the domain header).  A
			   zero offset specifies the first byte of the ID field,
			   etc.
			   The compression scheme allows a domain name in a message to be
			   represented as either:
			      - a sequence of labels ending in a zero octet
			      - a pointer
			      - a sequence of labels ending with a pointer
			*/
			if index+2 > len(data) {
				return nil, 0, ErrParseFrame
			}
			offsetp := int(binary.BigEndian.Uint16(data[index:index+2]) & 0x3fff)
			if offsetp > len(data) {
				return nil, 0, ErrParseFrame
			}
			// This looks a little tricky, but actually isn't.  Because of how
			// decodeName is written, calling it appends the decoded name to the
			// current buffer.  We already have the start of the buffer, then, so
			// once this call is done buffer[start:] will contain our full name.
			_, _, err := decodeName(data, offsetp, buffer, level+1)
			if err != nil {
				return nil, 0, err
			}
			index++ // pointer is two bytes, so add an extra byte here.
			break loop
		/* EDNS, or other DNS option ? */
		case 0x40: // RFC 2673
			return nil, 0, fmt.Errorf("qname '0x40' - RFC 2673 unsupported yet (data=%x index=%d)",
				data[index], index)

		case 0x80:
			return nil, 0, fmt.Errorf("qname '0x80' unsupported yet (data=%x index=%d)",
				data[index], index)
		}

		if index >= len(data) {
			return nil, 0, ErrParseFrame
		}
	}
	if len(*buffer) <= start {
		return (*buffer)[start:], index + 1, nil
	}
	return (*buffer)[start+1:], index + 1, nil
}
