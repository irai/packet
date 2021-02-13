package icmp6

import (
	"log"
	"net"
	"time"

	"github.com/mdlayher/ndp"
)

/**
func (s *Handler) SetPrefixes(prefixes []net.IPNet) error {
	s.mutex.Lock()
	s.prefixes = prefixes
	s.mutex.Unlock()
	return s.RouterAdvertisement(nil)
}
***/

func (h *Handler) RouterAdvertisement(router Router, addr *net.IPAddr) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if len(router.Prefixes) == 0 {
		return nil
	}
	if addr == nil {
		addr = &net.IPAddr{
			IP:   net.IPv6linklocalallnodes,
			Zone: h.ifi.Name,
		}
	}

	var options []ndp.Option

	if len(router.Prefixes) > 0 {
		addrs, err := h.ifi.Addrs()
		if err != nil {
			return err
		}
		var linkLocal net.IP
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipv6LinkLocal.Contains(ipnet.IP) {
				linkLocal = ipnet.IP
				break
			}
		}
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
	log.Printf("sending to %s", addr)
	if _, err := h.pc.WriteTo(mb, nil, addr); err != nil {
		return err
	}
	return nil
}
