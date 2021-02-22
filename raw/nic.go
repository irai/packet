package raw

import (
	"fmt"
	"log"
	"net"
)

// GetNICInfo returns the interface configuration
//
// TODO: use routing package to identify default router
// https://github.com/google/gopacket/tree/v1.1.19/routing
func GetNICInfo(nic string) (mac net.HardwareAddr, ipNet4 net.IPNet, ipNet6LLA net.IPNet, ipNet6GUA net.IPNet, err error) {

	all, err := net.Interfaces()
	for _, v := range all {
		log.Print("interface name ", v.Name, v.HardwareAddr.String())
	}

	ifi, err := net.InterfaceByName(nic)
	if err != nil {
		return nil, net.IPNet{}, net.IPNet{}, net.IPNet{}, err
	}

	mac = ifi.HardwareAddr

	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, net.IPNet{}, net.IPNet{}, net.IPNet{}, err
	}

	for i := range addrs {
		ip, ipNet, err := net.ParseCIDR(addrs[i].String())
		if err != nil {
			log.Printf("NIC cannot parse IP %s error %s ", addrs[i].String(), err)
			continue
		}

		if ipNet.IP.To4() != nil && ipNet.IP.IsGlobalUnicast() {
			ipNet4 = net.IPNet{IP: ip, Mask: ipNet.Mask}
		}
		if ipNet.IP.To16() != nil && ipNet.IP.To4() == nil {
			if ipNet.IP.IsLinkLocalUnicast() {
				ipNet6LLA = net.IPNet{IP: ip, Mask: ipNet.Mask}
			}
			if ipNet.IP.IsGlobalUnicast() {
				ipNet6GUA = net.IPNet{IP: ip, Mask: ipNet.Mask}
			}
		}
	}

	if ipNet4.IP == nil || ipNet4.IP.IsUnspecified() {
		return nil, net.IPNet{}, net.IPNet{}, net.IPNet{}, fmt.Errorf("ipv4 not found on interface")
	}

	return mac, ipNet4, ipNet6LLA, ipNet6GUA, nil
}
