package icmp6

import (
	"net"
	"time"

	"github.com/irai/packet"
)

func (h *Handler) SendRouterAdvertisement(router *Router, dstAddr packet.Addr) error {
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
		NewMTU(uint32(h.engine.NICInfo.IFI.MTU)),
		&LinkLayerAddress{
			Direction: Source,
			Addr:      h.engine.NICInfo.HostMAC,
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

	return h.sendPacket(packet.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostLLA.IP}, dstAddr, mb)
}

func (h *Handler) SendRouterSolicitation() error {
	m := &RouterSolicitation{
		Options: []Option{
			&LinkLayerAddress{
				Direction: Source,
				Addr:      h.engine.NICInfo.HostMAC,
			},
		},
	}
	mb, err := MarshalMessage(m)
	if err != nil {
		return err
	}

	return h.sendPacket(packet.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostLLA.IP}, packet.IP6AllNodesAddr, mb)
}

func (h *Handler) SendNeighborAdvertisement(ip net.IP, dstAddr packet.Addr) error {
	m := &NeighborAdvertisement{
		Router:        true,
		Solicited:     true,
		Override:      true,
		TargetAddress: ip,
		Options: []Option{
			&LinkLayerAddress{
				Direction: Target,
				Addr:      h.engine.NICInfo.HostMAC,
			},
		},
	}
	mb, err := MarshalMessage(m)
	if err != nil {
		return err
	}

	return h.sendPacket(packet.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostLLA.IP}, dstAddr, mb)
}

// SendNeighbourSolicitation send an ICMP6 NS packet.
func (h *Handler) SendNeighbourSolicitation(ip net.IP) error {
	m := &NeighborSolicitation{
		TargetAddress: ip,
		Options: []Option{
			&LinkLayerAddress{
				Direction: Source,
				Addr:      h.engine.NICInfo.HostMAC,
			},
		},
	}
	mb, err := MarshalMessage(m)
	if err != nil {
		return err
	}

	return h.sendPacket(packet.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostLLA.IP}, packet.IP6AllNodesAddr, mb)
}
