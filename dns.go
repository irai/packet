package packet

import (
	"encoding/binary"
	"fmt"
	"net"
)

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
func (p DNS) Decode() ([]DNSQuestion, DNSAnswers, error) {
	// buffer for doing name decoding.  We use a single reusable buffer to avoid
	// name decoding on a single object via multiple DecodeFromBytes calls
	// requiring constant allocation of small byte slices.
	var buffer []byte

	index := 12
	questions, index, err := p.decodeQuestion(index, &buffer)
	if err != nil {
		fmt.Printf("dns   : error decoding questions %s %s", err, p)
		return nil, DNSAnswers{}, err
	}

	answers, _, err := p.decodeAnswers(index, &buffer)
	if err != nil {
		fmt.Printf("dns   : error decoding answers %s %s", err, p)
		return nil, DNSAnswers{}, err
	}

	return questions, answers, nil
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

func (p DNS) decodeQuestion(index int, buffer *[]byte) ([]DNSQuestion, int, error) {
	var list []DNSQuestion

	for i := 0; i < int(p.QDCount()); i++ {
		if index+6 > len(p) { // must have at least 2 bytes name, 4 bytes type and class
			return []DNSQuestion{}, 0, ErrParseMessage
		}
		name, endq, err := decodeName(p, index, buffer, 1)
		if err != nil {
			return []DNSQuestion{}, 0, err
		}
		fmt.Println("TRACE name", string(name), endq)

		d := DNSQuestion{}
		d.Name = string(name)
		d.Type = binary.BigEndian.Uint16(p[endq : endq+2])    // 2 bytes
		d.Class = binary.BigEndian.Uint16(p[endq+2 : endq+4]) // 2 bytes
		list = append(list, d)
		index = endq + 4 // 4 bytes type and class
	}
	return list, index, nil
}

type IPResourceRecord struct {
	Name string
	IP   net.IP
	TTL  uint32
}

type DNSAnswers struct {
	IP4List   []IPResourceRecord
	IP6List   []IPResourceRecord
	CNAMEList []string
}

// decode decodes the resource record, returning the total length of the record.
func (p DNS) decodeAnswers(offset int, buffer *[]byte) (DNSAnswers, int, error) {
	answers := DNSAnswers{}

	for i := 0; i < int(p.ANCount()); i++ {
		name, endq, err := decodeName(p, offset, buffer, 1)
		if err != nil {
			return DNSAnswers{}, 0, fmt.Errorf("invalid label: %w", err)
		}

		t := binary.BigEndian.Uint16(p[endq : endq+2]) // type
		// class = binary.BigEndian.Uint16(p[endq+2 : endq+4])
		ttl := binary.BigEndian.Uint32(p[endq+4 : endq+8]) // number of seconds the RR can be cached
		dataLen := binary.BigEndian.Uint16(p[endq+8 : endq+10])
		offset = endq + 10 + int(dataLen)
		if offset > len(p) {
			return DNSAnswers{}, 0, fmt.Errorf("invalid resource record len: %w", ErrInvalidLen)
		}

		switch t {
		case 1: // A
			if dataLen != 4 {
				return DNSAnswers{}, 0, fmt.Errorf("invalid A data len: %w", ErrInvalidLen)
			}
			ip := net.IP(p[endq+10 : endq+10+4])
			answers.IP4List = append(answers.IP4List, IPResourceRecord{Name: string(name), IP: CopyIP(ip), TTL: ttl})

		case 28: // AAAA
			if dataLen != 16 {
				return DNSAnswers{}, 0, fmt.Errorf("invalid AAAA data len: %w", ErrInvalidLen)
			}
			ip := net.IP(p[endq+10 : endq+10+16])
			answers.IP6List = append(answers.IP6List, IPResourceRecord{Name: string(name), IP: CopyIP(ip), TTL: ttl})

		case 5: // CNAME
			name, endq, err = decodeName(p, endq+10, buffer, 1)
			if err != nil {
				fmt.Println("TRACE data len", dataLen)
				return DNSAnswers{}, 0, fmt.Errorf("invalid CNAME data: %w", err)
			}
			answers.CNAMEList = append(answers.CNAMEList, string(name))
		}
	}

	return answers, offset, nil
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
