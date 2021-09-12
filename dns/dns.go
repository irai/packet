package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
	"inet.af/netaddr"
)

var Debug bool

const module = "dns"

type DNSHandler struct {
	session   *packet.Session
	DNSTable  map[string]DNSEntry // store dns records
	mutex     sync.RWMutex
	mconn4    *net.UDPConn
	mconn6    *net.UDPConn
	ssdpconn4 *net.UDPConn
}

func New(session *packet.Session) (h *DNSHandler, err error) {
	h = new(DNSHandler)
	h.session = session
	h.DNSTable = make(map[string]DNSEntry, 256)

	// Resgiter for MDNS multicast
	if h.mconn4, err = net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: mdnsIPv4Addr.IP, Port: int(mdnsIPv4Addr.Port)}); err != nil {
		return nil, fmt.Errorf("failed to bind to multicast udp4 port: %w", err)
	}
	if h.mconn6, err = net.ListenMulticastUDP("udp6", nil, &net.UDPAddr{IP: mdnsIPv6Addr.IP, Port: int(mdnsIPv6Addr.Port)}); err != nil {
		log.Printf("MDNS: Failed to bind to udp6 port: %v", err)
	}

	// Register for ssdp multicast
	if h.ssdpconn4, err = net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: ssdpIPv4Addr.IP, Port: int(ssdpIPv4Addr.Port)}); err != nil {
		return nil, fmt.Errorf("failed to bind to ssdp ipv4 port: %w", err)
	}
	return h, nil
}

func (h *DNSHandler) Start() error {
	if err := h.SendNBNSNodeStatus(); err != nil {
		return err
	}
	return nil
}

type NameResourceRecord struct {
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
	CNameRecords map[string]NameResourceRecord
	PTRRecords   map[string]IPResourceRecord
}

// NameEntry holds a name entry
type NameEntry struct {
	Addr         packet.Addr
	Name         string
	Model        string
	Manufacturer string
	OS           string
}

func (n NameEntry) FastLog(l *fastlog.Line) *fastlog.Line {
	l.Struct(n.Addr)
	l.String("name", n.Name)
	l.String("model", n.Model)
	return l
}

// copy returns a deep copy of DNSEntry
func (d DNSEntry) copy() DNSEntry {
	e := DNSEntry{Name: d.Name}
	e.IP4Records = make(map[netaddr.IP]IPResourceRecord, len(d.IP4Records))
	e.IP6Records = make(map[netaddr.IP]IPResourceRecord, len(d.IP6Records))
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

	var b strings.Builder
	b.Grow(512)
	b.WriteString("dns   : name=")
	b.WriteString(d.Name)
	b.WriteString(" ip4=[ ")
	for _, v := range d.IP4Records {
		b.WriteString(v.IP.String())
		b.WriteString(" ")
	}
	b.WriteString("] ip6=[ ")
	for _, v := range d.IP6Records {
		b.WriteString(v.IP.String())
		b.WriteString(" ")
	}
	b.WriteString("] cname=[ ")
	for _, v := range d.CNameRecords {
		b.WriteString(v.CName)
		b.WriteString(" ")
	}
	if len(d.PTRRecords) > 0 {
		b.WriteString("] ptr=[ ")
		for _, v := range d.PTRRecords {
			b.WriteString(v.IP.String())
			b.WriteString(" ")
		}
	}
	b.WriteString("]")
	fmt.Println(b.String())
}

// DNS is specified in RFC 1034 / RFC 1035
// see : https://github.com/google/gopacket/blob/master/layers/dns.go
//
// We maintain a table of all DNS entries in the session.
var dnsMutex sync.RWMutex // dns table mutex

// DNS maps a domain name server frame
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
	return packet.ErrFrameLen
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

func newDNSEntry() (entry DNSEntry) {
	entry.IP4Records = make(map[netaddr.IP]IPResourceRecord)
	entry.IP6Records = make(map[netaddr.IP]IPResourceRecord)
	entry.CNameRecords = make(map[string]NameResourceRecord)
	entry.PTRRecords = make(map[string]IPResourceRecord)
	return entry
}

func dnsQueryMarshal(tranID uint16, flags uint16, encodedName []byte, questionType uint16) DNS {
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

func (p DNS) decode() (e DNSEntry, err error) {
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

	e = newDNSEntry()

	dnsMutex.Lock()
	defer dnsMutex.Unlock()

	if _, _, err = e.decodeAnswers(p, index, &buffer); err != nil {
		fmt.Printf("dns   : error decoding answers %s %s", err, p)
		return e, err
	}

	return e, nil
}

func (e *DNSEntry) decodeQuestion(p DNS, index int, buffer *[]byte) (int, error) {
	if p.QDCount() != 1 { // assume a single question
		return -1, packet.ErrParseFrame
	}

	// get first answer
	if index+6 > len(p) { // must have at least 2 bytes name, 4 bytes type and class
		return -1, packet.ErrParseFrame
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
//
// not goroutine safe:
//   must acquire lock before calling as function will update maps
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
			return 0, false, fmt.Errorf("invalid resource record len: %w", packet.ErrInvalidLen)
		}

		switch t {
		case 1: // A
			if dataLen != 4 {
				return 0, false, fmt.Errorf("invalid A data len: %w", packet.ErrInvalidLen)
			}
			ip, _ := netaddr.FromStdIPRaw(net.IP(p[endq+10 : endq+10+4]))
			if _, found := e.IP4Records[ip]; !found {
				e.IP4Records[ip] = IPResourceRecord{Name: string(name), IP: ip, TTL: ttl}
				updated = true
			}

		case 28: // AAAA
			if dataLen != 16 {
				return 0, false, fmt.Errorf("invalid AAAA data len: %w", packet.ErrInvalidLen)
			}
			ip, _ := netaddr.FromStdIPRaw(net.IP(p[endq+10 : endq+10+16]))
			if _, found := e.IP6Records[ip]; !found {
				e.IP6Records[ip] = IPResourceRecord{Name: string(name), IP: ip, TTL: ttl}
				updated = true
			}

		case 5: // CNAME

			var cname []byte
			cname, _, err = decodeName(p, endq+10, buffer, 1)
			if err != nil {
				return 0, false, fmt.Errorf("invalid CNAME data: %w", err)
			}
			n := string(name)
			if _, found := e.CNameRecords[n]; !found {
				r := NameResourceRecord{Name: n, TTL: ttl, CName: string(cname)}
				e.CNameRecords[r.Name] = r
				updated = true
			}

		case 15: // MX record
			if Debug {
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
			ip := netaddr.IPv4(tmp[3], tmp[2], tmp[1], tmp[0])
			var ptr []byte
			ptr, _, err = decodeName(p, endq+10, buffer, 1)
			if err != nil {
				return 0, false, fmt.Errorf("invalid PTR data: %w", err)
			}
			r := IPResourceRecord{Name: string(ptr), TTL: ttl, IP: ip}
			if _, found := e.PTRRecords[r.Name]; !found {
				e.PTRRecords[r.Name] = r
				updated = true
			}
			if Debug {
				fmt.Printf("dns   : received PTR record response ptr=%s ip=%s\n", r.Name, r.IP)
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
		return nil, 0, packet.ErrParseFrame
	} else if offset >= len(data) {
		return nil, 0, packet.ErrParseFrame
	} else if offset < 0 {
		return nil, 0, packet.ErrParseFrame
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
				return nil, 0, packet.ErrParseFrame
			} else if index2 < index+1 || index2 > len(data) {
				return nil, 0, packet.ErrParseFrame
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
				return nil, 0, packet.ErrParseFrame
			}
			offsetp := int(binary.BigEndian.Uint16(data[index:index+2]) & 0x3fff)
			if offsetp > len(data) {
				return nil, 0, packet.ErrParseFrame
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
			return nil, 0, packet.ErrParseFrame
		}
	}
	if len(*buffer) <= start {
		return (*buffer)[start:], index + 1, nil
	}
	return (*buffer)[start+1:], index + 1, nil
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

// reverseDNS query the PTR record for ip
// return ErrNotFound if there is no PTR record
func ReverseDNS(ip netaddr.IP) error {
	if Debug {
		fmt.Printf("dns   : reverse lookup for ip=%s\n", ip)
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, net.JoinHostPort(packet.CloudFlareDNS1.String(), "53")) //CloudFlare
		},
	}

	names, err := resolver.LookupAddr(context.TODO(), ip.String())
	if err != nil {
		// errors.As(err, &dnsErr) - as not implemented yet
		dnsErr, ok := err.(*net.DNSError)
		if ok && dnsErr.IsNotFound {
			if Debug {
				fmt.Printf("dns   : reverse lookup not found for ip=%s: %s %+v\n", ip, err, *dnsErr)
			}
			return packet.ErrNotFound
		}
		return err
	}
	if Debug {
		// fmt.Printf("dns   : reverse dns success ip=%s names=%v\n", ip, names)
		fastlog.NewLine(module, "reverse dns ok").String("ip", ip.String()).StringArray("names", names)
	}
	return nil
}

// ProcessDNS parse the DNS packet and record in DNS table.
//
// It returns a copy of the DNSEntry that is free from race conditions. The caller has a unique copy.
//
// TODO: optimise copy only on new values
func (h *DNSHandler) ProcessDNS(host *packet.Host, ether packet.Ether, payload []byte) (e DNSEntry, err error) {
	p := DNS(payload)
	if err := p.IsValid(); err != nil {
		return DNSEntry{}, err
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

	dnsMutex.Lock()
	defer dnsMutex.Unlock()

	e, found := h.DNSTable[tmp.Name]
	if !found {
		e = newDNSEntry()
		e.Name = tmp.Name
		e.IP4Records = make(map[netaddr.IP]IPResourceRecord)
		e.IP6Records = make(map[netaddr.IP]IPResourceRecord)
		e.CNameRecords = make(map[string]NameResourceRecord)
		e.PTRRecords = make(map[string]IPResourceRecord)
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
		return e.copy(), nil // return a copy to avoid race on maps
	}
	return DNSEntry{}, nil
}
