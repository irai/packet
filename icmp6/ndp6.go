package icmp6

import (
	"github.com/irai/packet/raw"
)

/**
func (s *Handler) SetPrefixes(prefixes []net.IPNet) error {
	s.mutex.Lock()
	s.prefixes = prefixes
	s.mutex.Unlock()
	return s.RouterAdvertisement(nil)
}
***/

func (h *Handler) RouterAdvertisement(router Router, addr *raw.Addr) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if len(router.Prefixes) == 0 {
		return nil
	}

	/***
	var options []ndp.Option

	if len(router.Prefixes) > 0 {
		if !linkLocal.Equal(net.IPv6zero) {
			options = append(options, &ndp.RecursiveDNSServer{
				Lifetime: 30 * time.Minute,
				Servers:  []net.IP{linkLocal},
			})
		}
	}

	for _, prefix := range router.Prefixes {
		options = append(options, &ndp.PrefixInformation{
			PrefixLength:                   uint8(prefix.PrefixLength),
			OnLink:                         true,
			AutonomousAddressConfiguration: true,
			ValidLifetime:                  2 * time.Hour,
			PreferredLifetime:              30 * time.Minute,
			Prefix:                         prefix.Prefix,
		})
	}

	options = append(options,
		&ndp.DNSSearchList{
			// TODO: audit all lifetimes and express them in relation to each other
			Lifetime: 20 * time.Minute,
			// TODO: single source of truth for search domain name
			DomainNames: []string{"lan"},
		},
		ndp.NewMTU(uint32(h.ifi.MTU)),
		&ndp.LinkLayerAddress{
			Direction: ndp.Source,
			Addr:      h.ifi.HardwareAddr,
		},
	)

	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit: 64,
		RouterLifetime:  30 * time.Minute,
		Options:         options,
	}

	mb, err := ndp.MarshalMessage(ra)
	if err != nil {
		return err
	}

	ether := raw.EtherMarshalBinary(nil, syscall.ETH_P_ARP, h.ifi.HardwareAddr, addr.MAC)
	ether.AppendPayload(mb)

	log.Printf("sending to %s", addr)
	if _, err := h.conn.WriteTo(mb, addr); err != nil {
		return err
	}
	***/
	return nil
}
