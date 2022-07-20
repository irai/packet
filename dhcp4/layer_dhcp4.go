package dhcp4

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

// DHCP4 port numbers
const (
	DHCP4ServerPort = 67
	DHCP4ClientPort = 68
)

type OpCode byte

// OpCodes
const (
	BootRequest OpCode = 1 // From Client
	BootReply   OpCode = 2 // From Server
)

type MessageType byte

// DHCP Message Type 53
const (
	Discover MessageType = 1
	Offer    MessageType = 2
	Request  MessageType = 3
	Decline  MessageType = 4
	ACK      MessageType = 5
	NAK      MessageType = 6
	Release  MessageType = 7
	Inform   MessageType = 8
)

type OptionCode byte

// DHCP Options
// see complete list here: https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
const (
	End                                      OptionCode = 255
	Pad                                      OptionCode = 0
	OptionSubnetMask                         OptionCode = 1
	OptionTimeOffset                         OptionCode = 2
	OptionRouter                             OptionCode = 3
	OptionTimeServer                         OptionCode = 4
	OptionNameServer                         OptionCode = 5
	OptionDomainNameServer                   OptionCode = 6
	OptionLogServer                          OptionCode = 7
	OptionCookieServer                       OptionCode = 8
	OptionLPRServer                          OptionCode = 9
	OptionImpressServer                      OptionCode = 10
	OptionResourceLocationServer             OptionCode = 11
	OptionHostName                           OptionCode = 12
	OptionBootFileSize                       OptionCode = 13
	OptionMeritDumpFile                      OptionCode = 14
	OptionDomainName                         OptionCode = 15
	OptionSwapServer                         OptionCode = 16
	OptionRootPath                           OptionCode = 17
	OptionExtensionsPath                     OptionCode = 18
	OptionIPForwardingEnableDisable          OptionCode = 19 // IP Layer Parameters per Host
	OptionNonLocalSourceRoutingEnableDisable OptionCode = 20
	OptionPolicyFilter                       OptionCode = 21
	OptionMaximumDatagramReassemblySize      OptionCode = 22
	OptionDefaultIPTimeToLive                OptionCode = 23
	OptionPathMTUAgingTimeout                OptionCode = 24
	OptionPathMTUPlateauTable                OptionCode = 25
	OptionInterfaceMTU                       OptionCode = 26 // IP Layer Parameters per Interface
	OptionAllSubnetsAreLocal                 OptionCode = 27
	OptionBroadcastAddress                   OptionCode = 28
	OptionPerformMaskDiscovery               OptionCode = 29
	OptionMaskSupplier                       OptionCode = 30
	OptionPerformRouterDiscovery             OptionCode = 31
	OptionRouterSolicitationAddress          OptionCode = 32
	OptionStaticRoute                        OptionCode = 33
	OptionTrailerEncapsulation               OptionCode = 34
	OptionARPCacheTimeout                    OptionCode = 35
	OptionEthernetEncapsulation              OptionCode = 36
	OptionRequestedIPAddress                 OptionCode = 50 // DHCP Extensions
	OptionIPAddressLeaseTime                 OptionCode = 51
	OptionOverload                           OptionCode = 52
	OptionDHCPMessageType                    OptionCode = 53
	OptionServerIdentifier                   OptionCode = 54
	OptionParameterRequestList               OptionCode = 55
	OptionMessage                            OptionCode = 56
	OptionMaximumDHCPMessageSize             OptionCode = 57
	OptionRenewalTimeValue                   OptionCode = 58
	OptionRebindingTimeValue                 OptionCode = 59
	OptionVendorClassIdentifier              OptionCode = 60
	OptionClientIdentifier                   OptionCode = 61
	OptionClasslessRouteFormat               OptionCode = 121
)

// A DHCP4 packet
type DHCP4 []byte

// DHCPv4 frame format
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
// +---------------+---------------+---------------+---------------+
// |                            xid (4)                            |
// +-------------------------------+-------------------------------+
// |           secs (2)            |           flags (2)           |
// +-------------------------------+-------------------------------+
// |                          ciaddr  (4)                          |
// +---------------------------------------------------------------+
// |                          yiaddr  (4)                          |
// +---------------------------------------------------------------+
// |                          siaddr  (4)                          |
// +---------------------------------------------------------------+
// |                          giaddr  (4)                          |
// +---------------------------------------------------------------+
// |                                                               |
// |                          chaddr  (16)                         |
// |                                                               |
// |                                                               |
// +---------------------------------------------------------------+
// |                                                               |
// |                          sname   (64)                         |
// +---------------------------------------------------------------+
// |                                                               |
// |                          file    (128)                        |
// +---------------------------------------------------------------+
// |cookie(4bytes)                                                 |
// |                          options (variable)                   |
// +---------------------------------------------------------------+
func (p DHCP4) OpCode() OpCode           { return OpCode(p[0]) }
func (p DHCP4) HType() byte              { return p[1] }
func (p DHCP4) HLen() byte               { return p[2] }
func (p DHCP4) Hops() byte               { return p[3] }
func (p DHCP4) XId() []byte              { return p[4:8] }
func (p DHCP4) Secs() uint16             { return binary.BigEndian.Uint16(p[8:10]) }
func (p DHCP4) Flags() uint16            { return binary.BigEndian.Uint16(p[10:12]) }
func (p DHCP4) CIAddr() netip.Addr       { return netip.AddrFrom4(*(*[4]byte)(p[12:16])) }
func (p DHCP4) YIAddr() netip.Addr       { return netip.AddrFrom4(*(*[4]byte)(p[16:20])) }
func (p DHCP4) SIAddr() netip.Addr       { return netip.AddrFrom4(*(*[4]byte)(p[20:24])) }
func (p DHCP4) GIAddr() netip.Addr       { return netip.AddrFrom4(*(*[4]byte)(p[24:28])) }
func (p DHCP4) CHAddr() net.HardwareAddr { return net.HardwareAddr(p[28 : 28+6]) }
func (p DHCP4) SName() []byte            { return trimNull(p[44 : 44+64]) }    // BOOTP legacy
func (p DHCP4) File() []byte             { return trimNull(p[108 : 108+128]) } // BOOTP legacy
func (p DHCP4) Cookie() []byte           { return p[236:240] }
func (p DHCP4) Options() []byte {
	if len(p) > 240 {
		return p[240:]
	}
	return nil
}

func (p DHCP4) IsValid() error {
	if len(p) < 240 { // Invalid size
		return packet.ErrFrameLen
	}
	if p.OpCode() != BootRequest && p.OpCode() != BootReply {
		return packet.ErrParseFrame
	}
	if p.HLen() != 6 { // Invalid frame - we only accept ethernet hardware addr
		return packet.ErrInvalidMAC
	}
	if err := p.validateOptions(); err != nil {
		return err
	}
	return nil
}

func (p DHCP4) String() string {
	l := Logger.Msg("")
	return p.FastLog(l).ToString()
}

func (p DHCP4) FastLog(line *fastlog.Line) *fastlog.Line {
	line.ByteArray("xid", p.XId())
	line.Uint8("opcode", uint8(p.OpCode()))
	line.MAC("chaddr", p.CHAddr())
	line.IP("ciaddr", p.CIAddr())
	line.IP("yiaddr", p.YIAddr())
	line.Int("len", len(p))
	return line
}

func trimNull(d []byte) []byte {
	for i, v := range d {
		if v == 0 {
			return d[:i]
		}
	}
	return d
}

func (p DHCP4) Broadcast() bool { return (p.Flags() & 0x8000) == 0x8000 }

func (p DHCP4) SetBroadcast(broadcast bool) {
	if p.Broadcast() != broadcast {
		p[10] ^= 128
	}
}

func (p DHCP4) SetOpCode(c OpCode) { p[0] = byte(c) }
func (p DHCP4) SetCHAddr(a net.HardwareAddr) {
	copy(p[28:44], a)
	p[2] = byte(len(a))
}
func (p DHCP4) SetHType(hType byte)     { p[1] = hType }
func (p DHCP4) SetHLen(hLen byte)       { p[2] = hLen }
func (p DHCP4) SetCookie(cookie []byte) { copy(p.Cookie(), cookie) }
func (p DHCP4) SetHops(hops byte)       { p[3] = hops }
func (p DHCP4) SetXId(xId []byte)       { copy(p.XId(), xId) }
func (p DHCP4) SetSecs(secs uint16)     { binary.BigEndian.PutUint16(p[8:10], secs) }
func (p DHCP4) SetFlags(flags uint16)   { binary.BigEndian.PutUint16(p[10:12], flags) }
func (p DHCP4) SetCIAddr(ip netip.Addr) { copy(p[12:16], ip.AsSlice()) }
func (p DHCP4) SetYIAddr(ip netip.Addr) { copy(p[16:20], ip.AsSlice()) }
func (p DHCP4) SetSIAddr(ip netip.Addr) { copy(p[20:24], ip.AsSlice()) }
func (p DHCP4) SetGIAddr(ip netip.Addr) { copy(p[24:28], ip.AsSlice()) }

// BOOTP legacy
func (p DHCP4) SetSName(sName []byte) {
	copy(p[44:108], sName)
	if len(sName) < 64 {
		p[44+len(sName)] = 0
	}
}

// BOOTP legacy
func (p DHCP4) SetFile(file []byte) {
	copy(p[108:236], file)
	if len(file) < 128 {
		p[108+len(file)] = 0
	}
}

// Map of DHCP options
type Options map[OptionCode][]byte

func (o Options) HostName() string {
	return string(o[OptionHostName])
}

func (o Options) RequestedIPAddress() net.IP {
	if tmp, ok := o[OptionRequestedIPAddress]; ok {
		return net.IP(tmp).To4()
	}
	return nil
}

func (o Options) ServerID() netip.Addr {
	if tmp, ok := o[OptionServerIdentifier]; ok {
		if ip, ok := netip.AddrFromSlice(tmp); ok && ip.Is4() && !ip.IsUnspecified() {
			return ip
		}
	}
	return netip.Addr{}
}

func (p DHCP4) validateOptions() error {
	opts := p.Options()
	if len(opts) < 2 {
		return packet.ErrParseFrame
	}
	for len(opts) >= 2 && OptionCode(opts[0]) != End {
		if OptionCode(opts[0]) == Pad {
			opts = opts[1:]
			continue
		}
		size := int(opts[1])
		if len(opts) < 2+size {
			return packet.ErrParseFrame
		}
		opts = opts[2+size:]
	}
	return nil
}

// Parses the packet's options into an Options map
// Caution: we return slices to the underlying byte array
func (p DHCP4) ParseOptions() Options {
	opts := p.Options()
	options := make(Options, 10)
	for len(opts) >= 2 && OptionCode(opts[0]) != End {
		if OptionCode(opts[0]) == Pad {
			opts = opts[1:]
			continue
		}
		size := int(opts[1])
		if len(opts) < 2+size {
			break
		}
		options[OptionCode(opts[0])] = opts[2 : 2+size]
		opts = opts[2+size:]
	}
	return options
}

func (p DHCP4) appendOptions(options Options, order []byte) int {
	if cap(p) < 240 {
		return 0
	}
	pos := 0
	buffer := make([]byte, 1024) // use a tmp buffer in case options point to the underlying array

	var optionsReplyParametersList = []byte{
		byte(OptionSubnetMask), // must appear before router options
		byte(OptionStaticRoute),
		byte(OptionRouter),
	}
	order = append(order, optionsReplyParametersList...)

	// first copy parameters in order
	for _, code := range order {
		if value, ok := options[OptionCode(code)]; ok {
			buffer[pos] = byte(code)
			buffer[pos+1] = byte(len(value))
			pos = pos + 2
			pos = pos + copy(buffer[pos:], value)
			delete(options, OptionCode(code))
		}
	}
	// second, copy any remaining options
	for code, value := range options {
		buffer[pos] = byte(code)
		buffer[pos+1] = byte(len(value))
		pos = pos + 2
		pos = pos + copy(buffer[pos:], value)
	}
	copy(p[240:cap(p)], buffer[:pos])
	return pos
}

// optionsLeaseTime - converts a time.Duration to a 4 byte slice, compatible
// with OptionIPAddressLeaseTime.
func optionsLeaseTime(d time.Duration) []byte {
	leaseBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(leaseBytes, uint32(d/time.Second))
	return leaseBytes
}

func zeroes(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0x00
	}
}

// Marshal returns the underlying slice as a DHCP4 frame. The returned slice is adjusted to the length of the DHCP frame.
// When replying to a DHCP request, you can pass nil to chaddr, ciaddr, yiadd, and xid to keep the underlying values.
func Marshall(b []byte, opcode OpCode, mt MessageType, chaddr net.HardwareAddr, ciaddr netip.Addr, yiaddr netip.Addr, xid []byte, broadcast bool, options Options, order []byte) DHCP4 {
	if cap(b) < 300 { // minimum packet size
		return nil
	}
	p := DHCP4(b[:cap(b)])
	zeroes(p[28+6 : 236]) // zero from chaddr (but keep first 6b of existing mac) , fname, file
	p.SetOpCode(opcode)
	p.SetHType(1) // Ethernet
	p.SetHLen(6)  // Ethernet mac len
	p.SetHops(0)
	if xid != nil {
		p.SetXId(xid)
	}
	p.SetSecs(0)
	p.SetFlags(0)
	p.SetCookie([]byte{99, 130, 83, 99})
	if ciaddr.Is4() {
		p.SetCIAddr(ciaddr)
	}
	if yiaddr.Is4() {
		p.SetYIAddr(yiaddr)
	}
	p.SetSIAddr(packet.IPv4zero)
	p.SetGIAddr(packet.IPv4zero)
	if chaddr != nil {
		p.SetCHAddr(chaddr)
	}
	p.SetBroadcast(broadcast)
	if options == nil {
		options = Options{}
	}
	options[OptionCode(OptionDHCPMessageType)] = []byte{byte(mt)}
	n := 240 + p.appendOptions(options, order)
	p[n] = byte(End)
	n++

	// PadToMinSize pads a packet so that when sent over UDP, the entire packet,
	// is 300 bytes (BOOTP min), to be compatible with really old devices.
	for ; n < 300; n++ {
		p[n] = 0x00
	}
	return p[:n]
}

// nakPacket returns a NACK reply packet.
// It reuses the buffer updating fields as required returning the same slice with updated len.
func nakPacket(req DHCP4, serverID, clientID []byte) DHCP4 {
	options := Options{}
	options[OptionServerIdentifier] = []byte(serverID) // rfc: must include
	if clientID != nil {
		options[OptionClientIdentifier] = clientID
	}
	return Marshall(req, BootReply, NAK, nil, packet.IPv4zero, packet.IPv4zero, nil, false, options, nil)
}
