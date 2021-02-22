package icmp6

import (
	"net"
	"time"

	"github.com/irai/packet/raw"
	"golang.org/x/net/ipv6"
)

/**
func (s *Handler) SetPrefixes(prefixes []net.IPNet) error {
	s.mutex.Lock()
	s.prefixes = prefixes
	s.mutex.Unlock()
	return s.RouterAdvertisement(nil)
}
***/

func (h *Handler) StartRADVS() error {
	// home: 2001:4479:1901:a001
	prefix := net.IP{0x20, 0x01, 0x44, 0x79, 0x19, 0x01, 0xa0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}

	// Cloudflare IP6:
	// 2606:4700:4700::1111
	// 2606:4700:4700::1001
	dns6 := net.IP{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11}

	router := Router{
		MAC:             h.ifi.HardwareAddr,
		IP:              h.LLA().IP,
		ManagedFlag:     false,
		OtherCondigFlag: false,
		MTU:             uint32(h.ifi.MTU),
		ReacheableTime:  int((time.Minute * 10).Milliseconds()), // Must be no greater than 3,600,000 milliseconds (1hour)
		RetransTimer:    int((time.Minute * 2).Milliseconds()),
		CurHopLimit:     1,
		DefaultLifetime: time.Minute * 30, // A value of zero means the router is not to be used as a default router
		Prefixes: []PrefixInformation{
			{
				PrefixLength:                   64,
				Prefix:                         prefix,
				AutonomousAddressConfiguration: true,
				ValidLifetime:                  time.Minute * 10,
				PreferredLifetime:              time.Minute * 5,
			},
		},
		RDNSS: &RecursiveDNSServer{
			Lifetime: time.Minute * 10,
			Servers:  []net.IP{dns6},
		},
	}
	return h.SendRouterAdvertisement(router, raw.Addr{MAC: EthAllNodesMulticast})
}

func (h *Handler) SendRouterAdvertisement(router Router, addr raw.Addr) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if len(router.Prefixes) == 0 {
		return nil
	}

	var options []Option

	if router.RDNSS != nil {
		options = append(options, &RecursiveDNSServer{
			Lifetime: router.RDNSS.Lifetime, // 30 * time.Minute,
			Servers:  router.RDNSS.Servers,
		})
	}

	for _, prefix := range router.Prefixes {
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
		NewMTU(uint32(h.ifi.MTU)),
		&LinkLayerAddress{
			Direction: Source,
			Addr:      h.ifi.HardwareAddr,
		},
	)

	ra := &RouterAdvertisement{
		CurrentHopLimit: 64,
		RouterLifetime:  30 * time.Minute,
		Options:         options,
	}

	icmpMessage := Message{
		Type: ipv6.ICMPTypeRouterAdvertisement,
		Code: 0,
		Body: ra,
	}

	mb, err := icmpMessage.Marshal()
	if err != nil {
		return err
	}

	return h.sendPacket(h.ifi.HardwareAddr, h.LLA().IP, EthAllNodesMulticast, IP6AllNodesMulticast, mb)
	/**
	ether := raw.EtherMarshalBinary(nil, syscall.ETH_P_IPV6, h.ifi.HardwareAddr, addr.MAC)
	ip6 := raw.IP6MarshalBinary(ether.Payload(), 1, h.ipNetLLA.IP, IP6AllNodesMulticast)
	ip6, err = ip6.AppendPayload(mb, uint8(ipv6.ICMPTypeMulticastRouterAdvertisement))
	ether, _ = ether.SetPayload(mb)

	log.Printf("icmp6: sending ra=%+v\n", ra)
	if _, err := h.conn.WriteTo(ether, &addr); err != nil {
		return err
	}
	return nil
	**/
}
