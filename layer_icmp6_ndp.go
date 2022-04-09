package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/ipv6"
)

const (

	// Minimum byte length values for each type of valid Message.
	nsLen = 20
	raLen = 12
	rsLen = 4
)

// errParseMessage is a sentinel which indicates an error from ParseMessage.
var errParseMessage = errors.New("failed to parse message")

// A NeighborAdvertisement is a Neighbor Advertisement message as
// described in RFC 4861, Section 4.4.
type NeighborAdvertisement struct {
	Router        bool
	Solicited     bool
	Override      bool
	TargetAddress net.IP
	TargetLLA     net.HardwareAddr // optional - TargetLLA option
}

// described in RFC 4861, Section 4.1.
type RouterAdvertisement struct {
	CurrentHopLimit           uint8
	ManagedConfiguration      bool
	OtherConfiguration        bool
	MobileIPv6HomeAgent       bool
	RouterSelectionPreference Preference
	NeighborDiscoveryProxy    bool
	RouterLifetime            time.Duration
	ReachableTime             time.Duration
	RetransmitTimer           time.Duration
	Options                   []Option
}

// A Preference is a NDP router selection or route preference value as
// described in RFC 4191, Section 2.1.
type Preference int

// Possible Preference values.
const (
	Medium      Preference = 0
	High        Preference = 1
	prfReserved Preference = 2
	Low         Preference = 3
)

// Type implements Message.
func (ra *RouterAdvertisement) Type() ipv6.ICMPType { return ipv6.ICMPTypeRouterAdvertisement }

func (ra *RouterAdvertisement) marshal() ([]byte, error) {
	if err := checkPreference(ra.RouterSelectionPreference); err != nil {
		return nil, err
	}

	b := make([]byte, raLen)

	b[0] = ra.CurrentHopLimit

	if ra.ManagedConfiguration {
		b[1] |= (1 << 7)
	}
	if ra.OtherConfiguration {
		b[1] |= (1 << 6)
	}
	if ra.MobileIPv6HomeAgent {
		b[1] |= (1 << 5)
	}
	if prf := uint8(ra.RouterSelectionPreference); prf != 0 {
		b[1] |= (prf << 3)
	}
	if ra.NeighborDiscoveryProxy {
		b[1] |= (1 << 2)
	}

	lifetime := ra.RouterLifetime.Seconds()
	binary.BigEndian.PutUint16(b[2:4], uint16(lifetime))

	reach := ra.ReachableTime / time.Millisecond
	binary.BigEndian.PutUint32(b[4:8], uint32(reach))

	retrans := ra.RetransmitTimer / time.Millisecond
	binary.BigEndian.PutUint32(b[8:12], uint32(retrans))

	ob, err := marshalOptions(ra.Options)
	if err != nil {
		return nil, err
	}

	b = append(b, ob...)

	return b, nil
}

/**
func (ra *RouterAdvertisement) unmarshal(b []byte) error {
	if len(b) < raLen {
		return io.ErrUnexpectedEOF
	}

	// Skip message body for options.
	options, err := parseOptions(b[raLen:])
	if err != nil {
		return err
	}

	var (
		mFlag = (b[1] & 0x80) != 0
		oFlag = (b[1] & 0x40) != 0
		hFlag = (b[1] & 0x20) != 0
		prf   = Preference((b[1] & 0x18) >> 3)
		pFlag = (b[1] & 0x04) != 0

		lifetime = time.Duration(binary.BigEndian.Uint16(b[2:4])) * time.Second
		reach    = time.Duration(binary.BigEndian.Uint32(b[4:8])) * time.Millisecond
		retrans  = time.Duration(binary.BigEndian.Uint32(b[8:12])) * time.Millisecond
	)

	// Per RFC 4191, Section 2.2:
	// "If the Reserved (10) value is received, the receiver MUST treat the
	// value as if it were (00)."
	if prf == prfReserved {
		prf = Medium
	}

	*ra = RouterAdvertisement{
		CurrentHopLimit:           b[0],
		ManagedConfiguration:      mFlag,
		OtherConfiguration:        oFlag,
		MobileIPv6HomeAgent:       hFlag,
		RouterSelectionPreference: prf,
		NeighborDiscoveryProxy:    pFlag,
		RouterLifetime:            lifetime,
		ReachableTime:             reach,
		RetransmitTimer:           retrans,
		Options:                   options,
	}

	return nil
}
**/

// A RouterSolicitation is a Router Solicitation message as
// described in RFC 4861, Section 4.1.
type RouterSolicitation struct {
	SourceLLA net.HardwareAddr
	Options   []Option
}

// Type implements Message.
func (rs *RouterSolicitation) Type() ipv6.ICMPType { return ipv6.ICMPTypeRouterSolicitation }

func (rs *RouterSolicitation) marshal() ([]byte, error) {
	// b contains reserved area.
	b := make([]byte, rsLen)

	ob, err := marshalOptions(rs.Options)
	if err != nil {
		return nil, err
	}

	b = append(b, ob...)

	return b, nil
}

/**
func (rs *RouterSolicitation) unmarshal(b []byte) error {
	if len(b) < rsLen {
		return io.ErrUnexpectedEOF
	}

	// Skip reserved area.
	options, err := parseOptions(b[rsLen:])
	if err != nil {
		return err
	}

	// A SourceLinkAddress is supposed to be included if the sender of the message is using an
	// IPv6 address other than the unspecified address (used during auto configuration).
	// SourceLinkAddress is the only valid option for Router Solicitation - RFC4861
	for _, v := range options {
		if slla, ok := v.(*LinkLayerAddress); ok {
			rs.SourceLLA = slla.Addr
		}
	}

	*rs = RouterSolicitation{
		Options: options,
	}

	return nil
}
***/

// checkPreference checks the validity of a Preference value.
func checkPreference(prf Preference) error {
	switch prf {
	case Low, Medium, High:
		return nil
	case prfReserved:
		return errors.New("ndp: cannot use reserved router selection preference value")
	default:
		return fmt.Errorf("ndp: unknown router selection preference value: %d", prf)
	}
}

func (h *Session) ICMP6SendRouterAdvertisement(prefixes []PrefixInformation, rdnss *RecursiveDNSServer, dstAddr Addr) error {
	if len(prefixes) == 0 {
		return nil
	}
	Logger.Msg("send router advertisement").Struct(dstAddr).Write()

	var options []Option
	if rdnss != nil {
		options = append(options, &RecursiveDNSServer{
			Lifetime: rdnss.Lifetime, // 30 * time.Minute,
			Servers:  rdnss.Servers,
		})
	}

	for _, prefix := range prefixes {
		options = append(options, &PrefixInformation{
			PrefixLength:                   uint8(prefix.PrefixLength),
			OnLink:                         true,
			AutonomousAddressConfiguration: true,
			ValidLifetime:                  2 * time.Hour,
			PreferredLifetime:              30 * time.Minute,
			Prefix:                         prefix.Prefix,
		})
	}

	options = append(options,
		&DNSSearchList{
			// TODO: audit all lifetimes and express them in relation to each other
			Lifetime: 20 * time.Minute,
			// TODO: single source of truth for search domain name
			DomainNames: []string{"lan"},
		},
		NewMTU(uint32(h.NICInfo.IFI.MTU)),
		&LinkLayerAddress{
			Direction: Source,
			MAC:       h.NICInfo.HostAddr4.MAC,
		},
	)

	ra := &RouterAdvertisement{
		CurrentHopLimit: 64,
		RouterLifetime:  30 * time.Minute,
		Options:         options,
	}

	mb, err := ra.marshal()
	if err != nil {
		return err
	}

	return h.icmp6SendPacket(Addr{MAC: h.NICInfo.HostAddr4.MAC, IP: h.NICInfo.HostLLA.Addr()}, dstAddr, mb)
}

func (h *Session) ICMP6SendRouterSolicitation() error {
	m := &RouterSolicitation{
		Options: []Option{
			&LinkLayerAddress{
				Direction: Source,
				MAC:       h.NICInfo.HostAddr4.MAC,
			},
		},
	}
	mb, err := m.marshal()
	if err != nil {
		return err
	}

	return h.icmp6SendPacket(Addr{MAC: h.NICInfo.HostAddr4.MAC, IP: h.NICInfo.HostLLA.Addr()}, IP6AllRoutersAddr, mb)
}

func (h *Session) ICMP6SendNeighborAdvertisement(srcAddr Addr, dstAddr Addr, targetAddr Addr) error {
	p := ICMP6NeighborAdvertisementMarshal(false, false, true, targetAddr)

	return h.icmp6SendPacket(srcAddr, dstAddr, p)
}

// SendNeighbourSolicitation send an ICMP6 NS
func (h *Session) ICMP6SendNeighbourSolicitation(srcAddr Addr, dstAddr Addr, targetIP netip.Addr) error {
	p, _ := ICMP6NeighborSolicitationMarshal(targetIP, h.NICInfo.HostAddr4.MAC)

	if Logger.IsDebug() {
		Logger.Msg("send NS request - src").Struct(srcAddr).Label("dst").Struct(dstAddr).IP("targetip", targetIP).Write()
	}
	return h.icmp6SendPacket(srcAddr, dstAddr, p)
}
