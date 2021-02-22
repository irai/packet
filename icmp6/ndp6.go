package icmp6

import (
	"net"
	"time"

	"github.com/irai/packet/raw"
)

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

	mb, err := MarshalMessage(ra)
	if err != nil {
		return err
	}

	return h.sendPacket(h.ifi.HardwareAddr, h.LLA().IP, EthAllNodesMulticast, IP6AllNodesMulticast, mb)
}

func (h *Handler) SendRouterSolicitation() error {
	m := &RouterSolicitation{
		Options: []Option{
			&LinkLayerAddress{
				Direction: Source,
				Addr:      h.ifi.HardwareAddr,
			},
		},
	}
	mb, err := MarshalMessage(m)
	if err != nil {
		return err
	}

	return h.sendPacket(h.ifi.HardwareAddr, h.LLA().IP, EthAllNodesMulticast, IP6AllNodesMulticast, mb)
}

func (h *Handler) SendNeighborAdvertisement(ip net.IP) error {
	m := &NeighborAdvertisement{
		Router:        true,
		Solicited:     true,
		Override:      true,
		TargetAddress: ip,
		Options: []Option{
			&LinkLayerAddress{
				Direction: Target,
				Addr:      h.ifi.HardwareAddr,
			},
		},
	}
	mb, err := MarshalMessage(m)
	if err != nil {
		return err
	}

	return h.sendPacket(h.ifi.HardwareAddr, h.LLA().IP, EthAllNodesMulticast, IP6AllNodesMulticast, mb)
}

// SendNeighbourSolicitation send an ICMP6 NS packet.
func (h *Handler) SendNeighbourSolicitation(ip net.IP) error {
	m := &NeighborSolicitation{
		TargetAddress: ip,
		Options: []Option{
			&LinkLayerAddress{
				Direction: Source,
				Addr:      h.ifi.HardwareAddr,
			},
		},
	}
	mb, err := MarshalMessage(m)
	if err != nil {
		return err
	}

	return h.sendPacket(h.ifi.HardwareAddr, h.LLA().IP, EthAllNodesMulticast, IP6AllNodesMulticast, mb)
}
