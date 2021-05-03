// dhcp4 IPv4 DHCP Library for Parsing and Creating DHCP Packets, along with basic DHCP server functionality
//
// Author: http://richard.warburton.it/
//
// Copyright: 2014 Skagerrak Software - http://www.skagerraksoftware.com/
package dhcp4

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

type Option struct {
	Code  OptionCode
	Value []byte
}
type OptionCode byte
type OpCode byte
type MessageType byte // Option 53

// A DHCP4 packet
type DHCP4 []byte

func (p DHCP4) IsValid() bool {
	if len(p) < 240 || p.HLen() > 16 { // Invalid size
		return false
	}
	return true
}

func (p DHCP4) LogString(clientID []byte, reqIP net.IP, name string, serverIP net.IP) string {
	var b strings.Builder
	b.Grow(80)
	b.WriteString("xid=\"")
	fmt.Fprintf(&b, "% x", p.XId())
	b.WriteString("\" clientid=\"")
	fmt.Fprintf(&b, "% x", clientID)
	b.WriteString("\" name=\"")
	b.WriteString(name)
	b.WriteString("\" reqIP=")
	b.WriteString(reqIP.String())
	b.WriteString(" chaddr=")
	b.WriteString(p.CHAddr().String())
	if serverIP != nil {
		b.WriteString(" serverIP=")
		b.WriteString(serverIP.String())
	}
	if Debug {
		b.WriteString(" ciaddr=")
		b.WriteString(p.CIAddr().String())
		b.WriteString(" brd=")
		fmt.Fprintf(&b, "%v", p.Broadcast())
	}
	return b.String()
}

func (p DHCP4) String() string {
	return fmt.Sprintf("opcode=%v chaddr=%s ciaddr=%s yiaddr=%s len=%d", p.OpCode(), p.CHAddr(), p.CIAddr(), p.YIAddr(), len(p))
}

func (p DHCP4) OpCode() OpCode { return OpCode(p[0]) }
func (p DHCP4) HType() byte    { return p[1] }
func (p DHCP4) HLen() byte     { return p[2] }
func (p DHCP4) Hops() byte     { return p[3] }
func (p DHCP4) XId() []byte    { return p[4:8] }
func (p DHCP4) Secs() []byte   { return p[8:10] } // Never Used?
func (p DHCP4) Flags() []byte  { return p[10:12] }
func (p DHCP4) CIAddr() net.IP { return net.IP(p[12:16]) }
func (p DHCP4) YIAddr() net.IP { return net.IP(p[16:20]) }
func (p DHCP4) SIAddr() net.IP { return net.IP(p[20:24]) }
func (p DHCP4) GIAddr() net.IP { return net.IP(p[24:28]) }
func (p DHCP4) CHAddr() net.HardwareAddr {
	hLen := p.HLen()
	if hLen > 16 { // Prevent chaddr exceeding p boundary
		hLen = 16
	}
	return net.HardwareAddr(p[28 : 28+hLen]) // max endPos 44
}

// 192 bytes of zeros BOOTP legacy

// BOOTP legacy
func (p DHCP4) SName() []byte { return trimNull(p[44:108]) }

// BOOTP legacy
func (p DHCP4) File() []byte { return trimNull(p[108:236]) }

func trimNull(d []byte) []byte {
	for i, v := range d {
		if v == 0 {
			return d[:i]
		}
	}
	return d
}

func (p DHCP4) Cookie() []byte { return p[236:240] }
func (p DHCP4) Options() []byte {
	if len(p) > 240 {
		return p[240:]
	}
	return nil
}

func (p DHCP4) Broadcast() bool { return p.Flags()[0] > 127 }

func (p DHCP4) SetBroadcast(broadcast bool) {
	if p.Broadcast() != broadcast {
		p.Flags()[0] ^= 128
	}
}

func (p DHCP4) SetOpCode(c OpCode) { p[0] = byte(c) }
func (p DHCP4) SetCHAddr(a net.HardwareAddr) {
	copy(p[28:44], a)
	p[2] = byte(len(a))
}
func (p DHCP4) SetHType(hType byte)     { p[1] = hType }
func (p DHCP4) SetCookie(cookie []byte) { copy(p.Cookie(), cookie) }
func (p DHCP4) SetHops(hops byte)       { p[3] = hops }
func (p DHCP4) SetXId(xId []byte)       { copy(p.XId(), xId) }
func (p DHCP4) SetSecs(secs []byte)     { copy(p.Secs(), secs) }
func (p DHCP4) SetFlags(flags []byte)   { copy(p.Flags(), flags) }
func (p DHCP4) SetCIAddr(ip net.IP)     { copy(p.CIAddr(), ip.To4()) }
func (p DHCP4) SetYIAddr(ip net.IP)     { copy(p.YIAddr(), ip.To4()) }
func (p DHCP4) SetSIAddr(ip net.IP)     { copy(p.SIAddr(), ip.To4()) }
func (p DHCP4) SetGIAddr(ip net.IP)     { copy(p.GIAddr(), ip.To4()) }

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

// Parses the packet's options into an Options map
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

func NewPacket(opCode OpCode) DHCP4 {
	p := make(DHCP4, 241)
	p.SetOpCode(opCode)
	p.SetHType(1) // Ethernet
	p.SetCookie([]byte{99, 130, 83, 99})
	p[240] = byte(End)
	return p
}

// Appends a DHCP option to the end of a packet
func (p *DHCP4) AddOption(o OptionCode, value []byte) {
	*p = append((*p)[:len(*p)-1], []byte{byte(o), byte(len(value))}...) // Strip off End, Add OptionCode and Length
	*p = append(*p, value...)                                           // Add Option Value
	*p = append(*p, byte(End))                                          // Add on new End
}

// Removes all options from packet.
func (p *DHCP4) StripOptions() {
	*p = append((*p)[:240], byte(End))
}

// Creates a request packet that a Client would send to a server.
func RequestPacket(mt MessageType, chAddr net.HardwareAddr, cIAddr net.IP, xId []byte, broadcast bool, options []Option) DHCP4 {
	p := NewPacket(BootRequest)
	p.SetCHAddr(chAddr)
	p.SetXId(xId)
	if cIAddr != nil {
		p.SetCIAddr(cIAddr)
	}
	p.SetBroadcast(broadcast)
	p.AddOption(OptionDHCPMessageType, []byte{byte(mt)})
	for _, o := range options {
		p.AddOption(o.Code, o.Value)
	}
	p.PadToMinSize()
	return p
}

// ReplyPacket creates a reply packet that a Server would send to a client.
// It uses the req Packet param to copy across common/necessary fields to
// associate the reply the request.
func ReplyPacket(req DHCP4, mt MessageType, serverID, yIAddr net.IP, leaseDuration time.Duration, options []Option) DHCP4 {
	p := NewPacket(BootReply)
	p.SetXId(req.XId())
	p.SetFlags(req.Flags())
	p.SetYIAddr(yIAddr)
	p.SetGIAddr(req.GIAddr())
	p.SetCHAddr(req.CHAddr())
	p.AddOption(OptionDHCPMessageType, []byte{byte(mt)})
	p.AddOption(OptionServerIdentifier, []byte(serverID))
	if leaseDuration > 0 {
		p.AddOption(OptionIPAddressLeaseTime, OptionsLeaseTime(leaseDuration))
	}
	for _, o := range options {
		p.AddOption(o.Code, o.Value)
	}
	p.PadToMinSize()
	return p
}

func DeclinePacket(mt MessageType, chAddr net.HardwareAddr, ciAddr net.IP, xId []byte, serverIP net.IP, options []Option) DHCP4 {
	p := NewPacket(BootRequest)
	p.SetCHAddr(chAddr)
	p.SetCIAddr(ciAddr)
	p.SetXId(xId)
	// p.AddOption(OptionClientIdentifier, clientID)
	p.AddOption(OptionServerIdentifier, serverIP.To4())
	p.AddOption(OptionDHCPMessageType, []byte{byte(mt)})
	p.AddOption(OptionMessage, []byte("netfilter decline"))
	for _, v := range options {
		p.AddOption(v.Code, v.Value)
	}
	p.PadToMinSize()
	return p
}

// PadToMinSize pads a packet so that when sent over UDP, the entire packet,
// is 300 bytes (BOOTP min), to be compatible with really old devices.
var padder [272]byte

func (p *DHCP4) PadToMinSize() {
	if n := len(*p); n < 272 {
		*p = append(*p, padder[:272-n]...)
	}
}

//go:generate stringer -type=OpCode

// OpCodes
const (
	BootRequest OpCode = 1 // From Client
	BootReply   OpCode = 2 // From Server
)

//go:generate stringer -type=MessageType

// DHCP Message Type 53
const (
	Discover MessageType = 1 // Broadcast Packet From Client - Can I have an IP?
	Offer    MessageType = 2 // Broadcast From Server - Here's an IP
	Request  MessageType = 3 // Broadcast From Client - I'll take that IP (Also start for renewals)
	Decline  MessageType = 4 // Broadcast From Client - Sorry I can't use that IP
	ACK      MessageType = 5 // From Server, Yes you can have that IP
	NAK      MessageType = 6 // From Server, No you cannot have that IP
	Release  MessageType = 7 // From Client, I don't need that IP anymore
	Inform   MessageType = 8 // From Client, I have this IP and there's nothing you can do about it
)

//go:generate stringer -type=OptionCode

// DHCP Options
const (
	End                          OptionCode = 255
	Pad                          OptionCode = 0
	OptionSubnetMask             OptionCode = 1
	OptionTimeOffset             OptionCode = 2
	OptionRouter                 OptionCode = 3
	OptionTimeServer             OptionCode = 4
	OptionNameServer             OptionCode = 5
	OptionDomainNameServer       OptionCode = 6
	OptionLogServer              OptionCode = 7
	OptionCookieServer           OptionCode = 8
	OptionLPRServer              OptionCode = 9
	OptionImpressServer          OptionCode = 10
	OptionResourceLocationServer OptionCode = 11
	OptionHostName               OptionCode = 12
	OptionBootFileSize           OptionCode = 13
	OptionMeritDumpFile          OptionCode = 14
	OptionDomainName             OptionCode = 15
	OptionSwapServer             OptionCode = 16
	OptionRootPath               OptionCode = 17
	OptionExtensionsPath         OptionCode = 18

	// IP Layer Parameters per Host
	OptionIPForwardingEnableDisable          OptionCode = 19
	OptionNonLocalSourceRoutingEnableDisable OptionCode = 20
	OptionPolicyFilter                       OptionCode = 21
	OptionMaximumDatagramReassemblySize      OptionCode = 22
	OptionDefaultIPTimeToLive                OptionCode = 23
	OptionPathMTUAgingTimeout                OptionCode = 24
	OptionPathMTUPlateauTable                OptionCode = 25

	// IP Layer Parameters per Interface
	OptionInterfaceMTU              OptionCode = 26
	OptionAllSubnetsAreLocal        OptionCode = 27
	OptionBroadcastAddress          OptionCode = 28
	OptionPerformMaskDiscovery      OptionCode = 29
	OptionMaskSupplier              OptionCode = 30
	OptionPerformRouterDiscovery    OptionCode = 31
	OptionRouterSolicitationAddress OptionCode = 32
	OptionStaticRoute               OptionCode = 33

	// Link Layer Parameters per Interface
	OptionTrailerEncapsulation  OptionCode = 34
	OptionARPCacheTimeout       OptionCode = 35
	OptionEthernetEncapsulation OptionCode = 36

	// TCP Parameters
	OptionTCPDefaultTTL        OptionCode = 37
	OptionTCPKeepaliveInterval OptionCode = 38
	OptionTCPKeepaliveGarbage  OptionCode = 39

	// Application and Service Parameters
	OptionNetworkInformationServiceDomain            OptionCode = 40
	OptionNetworkInformationServers                  OptionCode = 41
	OptionNetworkTimeProtocolServers                 OptionCode = 42
	OptionVendorSpecificInformation                  OptionCode = 43
	OptionNetBIOSOverTCPIPNameServer                 OptionCode = 44
	OptionNetBIOSOverTCPIPDatagramDistributionServer OptionCode = 45
	OptionNetBIOSOverTCPIPNodeType                   OptionCode = 46
	OptionNetBIOSOverTCPIPScope                      OptionCode = 47
	OptionXWindowSystemFontServer                    OptionCode = 48
	OptionXWindowSystemDisplayManager                OptionCode = 49
	OptionNetworkInformationServicePlusDomain        OptionCode = 64
	OptionNetworkInformationServicePlusServers       OptionCode = 65
	OptionMobileIPHomeAgent                          OptionCode = 68
	OptionSimpleMailTransportProtocol                OptionCode = 69
	OptionPostOfficeProtocolServer                   OptionCode = 70
	OptionNetworkNewsTransportProtocol               OptionCode = 71
	OptionDefaultWorldWideWebServer                  OptionCode = 72
	OptionDefaultFingerServer                        OptionCode = 73
	OptionDefaultInternetRelayChatServer             OptionCode = 74
	OptionStreetTalkServer                           OptionCode = 75
	OptionStreetTalkDirectoryAssistance              OptionCode = 76

	OptionRelayAgentInformation OptionCode = 82

	// DHCP Extensions
	OptionRequestedIPAddress     OptionCode = 50
	OptionIPAddressLeaseTime     OptionCode = 51
	OptionOverload               OptionCode = 52
	OptionDHCPMessageType        OptionCode = 53
	OptionServerIdentifier       OptionCode = 54
	OptionParameterRequestList   OptionCode = 55
	OptionMessage                OptionCode = 56
	OptionMaximumDHCPMessageSize OptionCode = 57
	OptionRenewalTimeValue       OptionCode = 58
	OptionRebindingTimeValue     OptionCode = 59
	OptionVendorClassIdentifier  OptionCode = 60
	OptionClientIdentifier       OptionCode = 61

	OptionTFTPServerName OptionCode = 66
	OptionBootFileName   OptionCode = 67

	OptionUserClass OptionCode = 77

	OptionClientArchitecture OptionCode = 93

	OptionTZPOSIXString    OptionCode = 100
	OptionTZDatabaseString OptionCode = 101

	OptionDomainSearch OptionCode = 119

	OptionClasslessRouteFormat OptionCode = 121

	// From RFC3942 - Options Used by PXELINUX
	OptionPxelinuxMagic      OptionCode = 208
	OptionPxelinuxConfigfile OptionCode = 209
	OptionPxelinuxPathprefix OptionCode = 210
	OptionPxelinuxReboottime OptionCode = 211
)

// SelectOrderOrAll has same functionality as SelectOrder, except if the order
// param is nil, whereby all options are added (in arbitrary order).
func (o Options) SelectOrderOrAll(order []byte) []Option {
	if order == nil {
		opts := make([]Option, 0, len(o))
		for i, v := range o {
			opts = append(opts, Option{Code: i, Value: v})
		}
		return opts
	}
	return o.SelectOrder(order)
}

// SelectOrder returns a slice of options ordered and selected by a byte array
// usually defined by OptionParameterRequestList.  This result is expected to be
// used in ReplyPacket()'s []Option parameter.
func (o Options) SelectOrder(order []byte) []Option {
	opts := make([]Option, 0, len(order))
	for _, v := range order {
		if data, ok := o[OptionCode(v)]; ok {
			opts = append(opts, Option{Code: OptionCode(v), Value: data})
		}
	}
	return opts
}

// OptionsLeaseTime - converts a time.Duration to a 4 byte slice, compatible
// with OptionIPAddressLeaseTime.
func OptionsLeaseTime(d time.Duration) []byte {
	leaseBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(leaseBytes, uint32(d/time.Second))
	return leaseBytes
}

/* Notes
A DHCP server always returns its own address in the 'server identifier' option.
DHCP defines a new 'client identifier' option that is used to pass an explicit client identifier to a DHCP server.
*/
