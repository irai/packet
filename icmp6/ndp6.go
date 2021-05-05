package icmp6

import (
	"net"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/model"
)

func (h *ICMP6Handler) SendRouterAdvertisement(router Router, dstAddr model.Addr) error {
	// h.mutex.Lock()
	// defer h.mutex.Unlock()
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

	mb, err := ra.marshal()
	if err != nil {
		return err
	}

	return h.sendPacket(model.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostLLA.IP}, dstAddr, mb)
}

func (h *ICMP6Handler) SendRouterSolicitation() error {
	m := &RouterSolicitation{
		Options: []Option{
			&LinkLayerAddress{
				Direction: Source,
				Addr:      h.engine.NICInfo.HostMAC,
			},
		},
	}
	mb, err := m.marshal()
	if err != nil {
		return err
	}

	return h.sendPacket(model.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostLLA.IP}, packet.IP6AllRoutersAddr, mb)
}

func (h *ICMP6Handler) SendNeighborAdvertisement(srcAddr model.Addr, dstAddr model.Addr) error {
	p := ICMP6NeighborAdvertisementMarshal(true, false, true, srcAddr.IP, srcAddr.MAC)

	return h.sendPacket(model.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostLLA.IP}, dstAddr, p)
}

// SendNeighbourSolicitation send an ICMP6 NS packet.
func (h *ICMP6Handler) SendNeighbourSolicitation(ip net.IP) error {
	p, _ := ICMP6NeighborSolicitationMarshal(ip, h.engine.NICInfo.HostMAC)

	return h.sendPacket(model.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostLLA.IP}, packet.IP6AllNodesAddr, p)
}
