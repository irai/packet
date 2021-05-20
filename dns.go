package packet

import (
	"encoding/binary"
	"fmt"
	"net"

	"inet.af/netaddr"
)

type CNameResourceRecord struct {
	Name  string
	CName string
	TTL   uint32
}

type IPResourceRecord struct {
	Name string
	IP   netaddr.IP
	TTL  uint32
}
type DNSEntry struct {
	Name         string
	IP4Records   map[netaddr.IP]IPResourceRecord
	IP6Records   map[netaddr.IP]IPResourceRecord
	CNameRecords map[string]CNameResourceRecord
}

func (d DNSEntry) IP4List() []netaddr.IP {
	list := make([]netaddr.IP, 0, len(d.IP4Records))
	for _, v := range d.IP4Records {
		list = append(list, v.IP)
	}
	return list
}

func (d DNSEntry) IP6List() []netaddr.IP {
	list := make([]netaddr.IP, 0, len(d.IP6Records))
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

func (d DNSEntry) print() {
	fmt.Printf("dns   : name=%s ip4=%+v\n", d.Name, d.IP4List())
	fmt.Printf("dns   : name=%s ip6=%+v\n", d.Name, d.IP6List())
	fmt.Printf("dns   : name=%s cname=%+v\n", d.Name, d.CNameList())
}

// DNS is specified in RFC 1034 / RFC 1035
// see : https://github.com/google/gopacket/blob/master/layers/dns.go

// DNS maps a domain name server frame
type DNS []byte

func (p DNS) IsValid() bool {
	return len(p) >= 12
}
func (p DNS) String() string {
	return fmt.Sprintf("qr=%v tc=%v rcode=%v qdcount=%v ancount=%v", p.QR(), p.TC(), p.ResponseCode(), p.QDCount(), p.ANCount())
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
func (p DNS) Decode() (e DNSEntry, err error) {
	// buffer for doing name decoding.  We use a single reusable buffer to avoid
	// name decoding on a single object via multiple DecodeFromBytes calls
	// requiring constant allocation of small byte slices.
	var buffer []byte

	index := 12
	index, err = e.decodeQuestion(p, index, &buffer)
	if err != nil {
		fmt.Printf("dns   : error decoding questions %s %s", err, p)
		return e, err
	}

	e.IP4Records = make(map[netaddr.IP]IPResourceRecord)
	e.IP6Records = make(map[netaddr.IP]IPResourceRecord)
	e.CNameRecords = make(map[string]CNameResourceRecord)

	if index, _, err = e.decodeAnswers(p, index, &buffer); err != nil {
		fmt.Printf("dns   : error decoding answers %s %s", err, p)
		return e, err
	}

	return e, nil
}

func (e *DNSEntry) decodeQuestion(p DNS, index int, buffer *[]byte) (int, error) {
	if p.QDCount() != 1 {
		return -1, ErrParseMessage
	}

	// get first answer
	if index+6 > len(p) { // must have at least 2 bytes name, 4 bytes type and class
		return -1, ErrParseMessage
	}
	name, endq, err := decodeName(p, index, buffer, 1)
	if err != nil {
		return -1, err
	}

	// d.Type = binary.BigEndian.Uint16(p[endq : endq+2])    // 2 bytes
	// d.Class = binary.BigEndian.Uint16(p[endq+2 : endq+4]) // 2 bytes
	index = endq + 4 // 4 bytes type and class
	e.Name = string(name)

	return index, nil
}

// decode decodes the resource record, returning the total length of the record.
func (e *DNSEntry) decodeAnswers(p DNS, offset int, buffer *[]byte) (int, bool, error) {

	var updated bool
	for i := 0; i < int(p.ANCount()); i++ {
		name, endq, err := decodeName(p, offset, buffer, 1)
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
			ip, _ := netaddr.FromStdIP(net.IP(p[endq+10 : endq+10+4]))
			if _, found := e.IP4Records[ip]; !found {
				e.IP4Records[ip] = IPResourceRecord{Name: string(name), IP: ip, TTL: ttl}
				updated = true
			}

		case 28: // AAAA
			if dataLen != 16 {
				return 0, false, fmt.Errorf("invalid AAAA data len: %w", ErrInvalidLen)
			}
			ip, _ := netaddr.FromStdIP(net.IP(p[endq+10 : endq+10+16]))
			if _, found := e.IP6Records[ip]; !found {
				e.IP6Records[ip] = IPResourceRecord{Name: string(name), IP: ip, TTL: ttl}
				updated = true
			}

		case 5: // CNAME

			var cname []byte
			cname, endq, err = decodeName(p, endq+10, buffer, 1)
			if err != nil {
				return 0, false, fmt.Errorf("invalid CNAME data: %w", err)
			}
			r := CNameResourceRecord{Name: string(name), TTL: ttl, CName: string(cname)}
			if _, found := e.CNameRecords[r.Name]; !found {
				e.CNameRecords[r.Name] = r
				updated = true
			}

		case 15: // MX record
			if Debug {
				fmt.Println("dns   : received MX record response - ignoring", string(name))
			}
		case 12: // PTR record
			if Debug {
				fmt.Println("dns   : received PTR record response - ignoring", string(name))
			}
		default:
			fmt.Println("dns   : unexpected dns resource record ", t, string(name))
		}
	}

	return offset, updated, nil
}

const maxRecursionLevel = 255

// decodeName extracted from https://github.com/google/gopacket/blob/master/layers/dns.go
func decodeName(data []byte, offset int, buffer *[]byte, level int) ([]byte, int, error) {
	if level > maxRecursionLevel {
		return nil, 0, ErrParseMessage
	} else if offset >= len(data) {
		return nil, 0, ErrParseMessage
	} else if offset < 0 {
		return nil, 0, ErrParseMessage
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
				return nil, 0, ErrParseMessage
			} else if index2 < index+1 || index2 > len(data) {
				return nil, 0, ErrParseMessage
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
				return nil, 0, ErrParseMessage
			}
			offsetp := int(binary.BigEndian.Uint16(data[index:index+2]) & 0x3fff)
			if offsetp > len(data) {
				return nil, 0, ErrParseMessage
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
			return nil, 0, ErrParseMessage
		}
	}
	if len(*buffer) <= start {
		return (*buffer)[start:], index + 1, nil
	}
	return (*buffer)[start+1:], index + 1, nil
}

func (h *Session) ProcessDNS(host *Host, ether Ether, payload []byte) (e DNSEntry, err error) {
	p := DNS(payload)
	if !p.IsValid() {
		return DNSEntry{}, ErrParseMessage
	}

	// buffer for doing name decoding.  We use a single reusable buffer to avoid
	// name decoding on a single object via multiple DecodeFromBytes calls
	// requiring constant allocation of small byte slices.
	var buffer []byte
	tmp := DNSEntry{}

	index := 12
	index, err = tmp.decodeQuestion(p, index, &buffer)
	if err != nil {
		fmt.Printf("dns   : error decoding questions %s %s", err, p)
		return DNSEntry{}, err
	}

	e, found := h.DNSTable[tmp.Name]
	if !found {
		e = tmp
		e.IP4Records = make(map[netaddr.IP]IPResourceRecord)
		e.IP6Records = make(map[netaddr.IP]IPResourceRecord)
		e.CNameRecords = make(map[string]CNameResourceRecord)
	}

	var updated bool
	if _, updated, err = e.decodeAnswers(p, index, &buffer); err != nil {
		fmt.Printf("dns   : error decoding answers %s %s", err, p)
		return DNSEntry{}, err
	}
	if updated {
		if Debug {
			e.print()
		}
		h.DNSTable[e.Name] = e
		return e, nil
	}
	return DNSEntry{}, nil
}
