package icmp6

import (
	"net"
	"time"

	"github.com/irai/packet"
)

func (h *Handler) SendRouterAdvertisement(router Router, dstAddr packet.Addr) error {
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
		NewMTU(uint32(h.session.NICInfo.IFI.MTU)),
		&LinkLayerAddress{
			Direction: Source,
			MAC:       h.session.NICInfo.HostMAC,
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

	return h.sendPacket(packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostLLA.IP}, dstAddr, mb)
}

func (h *Handler) SendRouterSolicitation() error {
	m := &RouterSolicitation{
		Options: []Option{
			&LinkLayerAddress{
				Direction: Source,
				MAC:       h.session.NICInfo.HostMAC,
			},
		},
	}
	mb, err := m.marshal()
	if err != nil {
		return err
	}

	return h.sendPacket(packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostLLA.IP}, packet.IP6AllRoutersAddr, mb)
}

func (h *Handler) SendNeighborAdvertisement(srcAddr packet.Addr, dstAddr packet.Addr) error {
	p := ICMP6NeighborAdvertisementMarshal(true, false, true, srcAddr.IP, srcAddr.MAC)

	return h.sendPacket(packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostLLA.IP}, dstAddr, p)
}

// SendNeighbourSolicitation send an ICMP6 NS packet.
func (h *Handler) SendNeighbourSolicitation(ip net.IP) error {
	p, _ := ICMP6NeighborSolicitationMarshal(ip, h.session.NICInfo.HostMAC)

	return h.sendPacket(packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostLLA.IP}, packet.IP6AllNodesAddr, p)
}
