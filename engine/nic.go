package engine

import (
	"fmt"
	"net"

	"github.com/irai/packet"
	"github.com/irai/packet/icmp"
)

// SegmentLAN will identify a free IP on the opposite half segment from the routerIP.
// This function will also test if the chosen IP is available before returning.
func SegmentLAN(nic string, homeLAN net.IPNet, hostIP net.IP, routerIP net.IP) (netfilterIP net.IPNet, err error) {
	if hostIP.To4() == nil || routerIP.To4() == nil {
		return netfilterIP, packet.ErrInvalidIP
	}

	// Special IPv4 addresses
	// 169.254.0.0/16 - Link local addresses - typically assigned when there is no DHCP server
	// 172.16.0.0/12 - Private network
	// 192.168.0.0/16 - Private network
	// 10.0.0.0/8 - Private network
	_, net169, _ := net.ParseCIDR("169.254.0.0/16")
	_, net172, _ := net.ParseCIDR("172.16.0.0/12")
	_, net192, _ := net.ParseCIDR("192.168.0.0/16")
	_, net10, _ := net.ParseCIDR("10.0.0.0/8")

	switch {
	case net169.Contains(routerIP):
	case net172.Contains(routerIP):
	case net192.Contains(routerIP):
	case net10.Contains(routerIP):
	default:
		fmt.Printf("packet: error unexpected IP network %+v\n", routerIP)
	}

	// Ignore large networks: we only need 128 hosts for our DHCP -
	// 128 hosts should be enought for all homes
	n, _ := homeLAN.Mask.Size()
	if n < 24 {
		n = 24
	}

	if n > 24 {
		err = fmt.Errorf("network mask too small (less than 8 bits) router %+v", homeLAN)
		return netfilterIP, err
	}

	// Set router address for netfilter
	// Router segment will be at the opposite end of the Home segment
	homeRouterIP := routerIP.To4() // make sure we are dealing with 4 bytes
	if homeRouterIP[3] < 128 {
		// 128 to 255 - but don't use network address 0 and broadcast 254
		netfilterIP.IP, err = locateFreeIP(nic, hostIP, homeRouterIP, 129, 254)
	} else {
		// 0 to 127 - but don't use network address 0 and broadcast 127
		netfilterIP.IP, err = locateFreeIP(nic, hostIP, homeRouterIP, 1, 126)
	}

	if err != nil {
		err = fmt.Errorf("cannot find free IP for router ")
		return netfilterIP, err
	}

	// Use the first bit to segment
	netfilterIP.Mask = net.IPv4Mask(255, 255, 255, 128)
	return netfilterIP, nil
}

func locateFreeIP(nic string, hostIP net.IP, ip net.IP, start uint8, end uint8) (newIP net.IP, err error) {
	newIP = packet.CopyIP(ip).To4()
	for i := start; i <= end; i++ {
		newIP[3] = i // save to variable

		// if host already set for this IP
		if hostIP.Equal(newIP) {
			return newIP, nil
		}

		// ping to populate arp table
		if nic != "" {
			icmp.ExecPing(ip.String()) // populate arp table
		}

		// check if arp table has the IP
		arpTable, err := packet.LoadLinuxARPTable(nic)
		if err != nil {
			return nil, err
		}
		for _, v := range arpTable {
			if v.IP.Equal(newIP) {
				fmt.Printf("packet: NIC netfilter target IP %s in use. Trying again...\n", newIP)
				continue
			}
		}
		return newIP, nil
	}
	return net.IPv4zero, fmt.Errorf("locatefreeip no ips available")
}
