package packet

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/irai/packet/fastlog"
)

// DHCP4 port numbers
const (
	DHCP4ServerPort = 67
	DHCP4ClientPort = 68
)

type DHCP4OpCode byte

// OpCodes
const (
	DHCP4BootRequest DHCP4OpCode = 1 // From Client
	DHCP4BootReply   DHCP4OpCode = 2 // From Server
)

type DHCP4MessageType byte

// DHCP Message Type 53
const (
	DHCP4Discover DHCP4MessageType = 1
	DHCP4Offer    DHCP4MessageType = 2
	DHCP4Request  DHCP4MessageType = 3
	DHCP4Decline  DHCP4MessageType = 4
	DHCP4ACK      DHCP4MessageType = 5
	DHCP4NAK      DHCP4MessageType = 6
	DHCP4Release  DHCP4MessageType = 7
	DHCP4Inform   DHCP4MessageType = 8
)

type DHCP4OptionCode byte

// DHCP Options
// see complete list here: https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
const (
	DHCP4End                                      DHCP4OptionCode = 255
	DHCP4Pad                                      DHCP4OptionCode = 0
	DHCP4OptionSubnetMask                         DHCP4OptionCode = 1
	DHCP4OptionTimeOffset                         DHCP4OptionCode = 2
	DHCP4OptionRouter                             DHCP4OptionCode = 3
	DHCP4OptionTimeServer                         DHCP4OptionCode = 4
	DHCP4OptionNameServer                         DHCP4OptionCode = 5
	DHCP4OptionDomainNameServer                   DHCP4OptionCode = 6
	DHCP4OptionLogServer                          DHCP4OptionCode = 7
	DHCP4OptionCookieServer                       DHCP4OptionCode = 8
	DHCP4OptionLPRServer                          DHCP4OptionCode = 9
	DHCP4OptionImpressServer                      DHCP4OptionCode = 10
	DHCP4OptionResourceLocationServer             DHCP4OptionCode = 11
	DHCP4OptionHostName                           DHCP4OptionCode = 12
	DHCP4OptionBootFileSize                       DHCP4OptionCode = 13
	DHCP4OptionMeritDumpFile                      DHCP4OptionCode = 14
	DHCP4OptionDomainName                         DHCP4OptionCode = 15
	DHCP4OptionSwapServer                         DHCP4OptionCode = 16
	DHCP4OptionRootPath                           DHCP4OptionCode = 17
	DHCP4OptionExtensionsPath                     DHCP4OptionCode = 18
	DHCP4OptionIPForwardingEnableDisable          DHCP4OptionCode = 19 // IP Layer Parameters per Host
	DHCP4OptionNonLocalSourceRoutingEnableDisable DHCP4OptionCode = 20
	DHCP4OptionPolicyFilter                       DHCP4OptionCode = 21
	DHCP4OptionMaximumDatagramReassemblySize      DHCP4OptionCode = 22
	DHCP4OptionDefaultIPTimeToLive                DHCP4OptionCode = 23
	DHCP4OptionPathMTUAgingTimeout                DHCP4OptionCode = 24
	DHCP4OptionPathMTUPlateauTable                DHCP4OptionCode = 25
	DHCP4OptionInterfaceMTU                       DHCP4OptionCode = 26 // IP Layer Parameters per Interface
	DHCP4OptionAllSubnetsAreLocal                 DHCP4OptionCode = 27
	DHCP4OptionBroadcastAddress                   DHCP4OptionCode = 28
	DHCP4OptionPerformMaskDiscovery               DHCP4OptionCode = 29
	DHCP4OptionMaskSupplier                       DHCP4OptionCode = 30
	DHCP4OptionPerformRouterDiscovery             DHCP4OptionCode = 31
	DHCP4OptionRouterSolicitationAddress          DHCP4OptionCode = 32
	DHCP4OptionStaticRoute                        DHCP4OptionCode = 33
	DHCP4OptionTrailerEncapsulation               DHCP4OptionCode = 34
	DHCP4OptionARPCacheTimeout                    DHCP4OptionCode = 35
	DHCP4OptionEthernetEncapsulation              DHCP4OptionCode = 36
	DHCP4OptionRequestedIPAddress                 DHCP4OptionCode = 50 // DHCP Extensions
	DHCP4OptionIPAddressLeaseTime                 DHCP4OptionCode = 51
	DHCP4OptionOverload                           DHCP4OptionCode = 52
	DHCP4OptionDHCPMessageType                    DHCP4OptionCode = 53
	DHCP4OptionServerIdentifier                   DHCP4OptionCode = 54
	DHCP4OptionParameterRequestList               DHCP4OptionCode = 55
	DHCP4OptionMessage                            DHCP4OptionCode = 56
	DHCP4OptionMaximumDHCPMessageSize             DHCP4OptionCode = 57
	DHCP4OptionRenewalTimeValue                   DHCP4OptionCode = 58
	DHCP4OptionRebindingTimeValue                 DHCP4OptionCode = 59
	DHCP4OptionVendorClassIdentifier              DHCP4OptionCode = 60
	DHCP4OptionClientIdentifier                   DHCP4OptionCode = 61
	DHCP4OptionClasslessRouteFormat               DHCP4OptionCode = 121
)

// DHCP4 represents a dhcp version 4 packet.
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
func (p DHCP4) OpCode() DHCP4OpCode      { return DHCP4OpCode(p[0]) }
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
		return ErrFrameLen
	}
	if p.OpCode() != DHCP4BootRequest && p.OpCode() != DHCP4BootReply {
		return ErrParseFrame
	}
	if p.HLen() != 6 { // Invalid frame - we only accept ethernet hardware addr
		return ErrInvalidMAC
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

func (p DHCP4) SetOpCode(c DHCP4OpCode) { p[0] = byte(c) }
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
type DHCP4Options map[DHCP4OptionCode][]byte

func (o DHCP4Options) HostName() string {
	return string(o[DHCP4OptionHostName])
}

func (o DHCP4Options) RequestedIPAddress() net.IP {
	if tmp, ok := o[DHCP4OptionRequestedIPAddress]; ok {
		return net.IP(tmp).To4()
	}
	return nil
}

func (o DHCP4Options) ServerID() netip.Addr {
	if tmp, ok := o[DHCP4OptionServerIdentifier]; ok {
		if ip, ok := netip.AddrFromSlice(tmp); ok && ip.Is4() && !ip.IsUnspecified() {
			return ip
		}
	}
	return netip.Addr{}
}

func (p DHCP4) validateOptions() error {
	opts := p.Options()
	if len(opts) < 2 {
		return ErrParseFrame
	}
	for len(opts) >= 2 && DHCP4OptionCode(opts[0]) != DHCP4End {
		if DHCP4OptionCode(opts[0]) == DHCP4Pad {
			opts = opts[1:]
			continue
		}
		size := int(opts[1])
		if len(opts) < 2+size {
			return ErrParseFrame
		}
		opts = opts[2+size:]
	}
	return nil
}

// Parses the packet's options into an Options map
// Caution: we return slices to the underlying byte array
func (p DHCP4) ParseOptions() DHCP4Options {
	opts := p.Options()
	options := make(DHCP4Options, 10)
	for len(opts) >= 2 && DHCP4OptionCode(opts[0]) != DHCP4End {
		if DHCP4OptionCode(opts[0]) == DHCP4Pad {
			opts = opts[1:]
			continue
		}
		size := int(opts[1])
		if len(opts) < 2+size {
			break
		}
		options[DHCP4OptionCode(opts[0])] = opts[2 : 2+size]
		opts = opts[2+size:]
	}
	return options
}

func (p DHCP4) AppendOptions(options DHCP4Options, order []byte) int {
	if cap(p) < 240 {
		return 0
	}
	pos := 0
	buffer := make([]byte, 1024) // use a tmp buffer in case options point to the underlying array

	var optionsReplyParametersList = []byte{
		byte(DHCP4OptionSubnetMask), // must appear before router options
		byte(DHCP4OptionStaticRoute),
		byte(DHCP4OptionRouter),
	}
	order = append(order, optionsReplyParametersList...)

	// first copy parameters in order
	for _, code := range order {
		if value, ok := options[DHCP4OptionCode(code)]; ok {
			buffer[pos] = byte(code)
			buffer[pos+1] = byte(len(value))
			pos = pos + 2
			pos = pos + copy(buffer[pos:], value)
			delete(options, DHCP4OptionCode(code))
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
func OptionsLeaseTime(d time.Duration) []byte {
	leaseBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(leaseBytes, uint32(d/time.Second))
	return leaseBytes
}

func zeroes(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0x00
	}
}

// EncodeDHCP4 returns the underlying slice as a DHCP4 frame. The returned slice is adjusted to the length of the DHCP frame.
// When replying to a DHCP request, you can pass nil to chaddr, ciaddr, yiadd, and xid to keep the underlying values.
func EncodeDHCP4(b []byte, opcode DHCP4OpCode, mt DHCP4MessageType, chaddr net.HardwareAddr, ciaddr netip.Addr, yiaddr netip.Addr, xid []byte, broadcast bool, options DHCP4Options, order []byte) DHCP4 {
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
	p.SetSIAddr(IPv4zero)
	p.SetGIAddr(IPv4zero)
	if chaddr != nil {
		p.SetCHAddr(chaddr)
	}
	p.SetBroadcast(broadcast)
	if options == nil {
		options = DHCP4Options{}
	}
	options[DHCP4OptionCode(DHCP4OptionDHCPMessageType)] = []byte{byte(mt)}
	n := 240 + p.AppendOptions(options, order)
	p[n] = byte(DHCP4End)
	n++

	// PadToMinSize pads a packet so that when sent over UDP, the entire packet,
	// is 300 bytes (BOOTP min), to be compatible with really old devices.
	for ; n < 300; n++ {
		p[n] = 0x00
	}
	return p[:n]
}
