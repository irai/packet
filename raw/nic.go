package raw

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

// GetNICInfo returns the interface configuration
//
// TODO: use routing package to identify default router
// https://github.com/google/gopacket/tree/v1.1.19/routing
func GetNICInfo(nic string) (ifi *net.Interface, ipNet4 net.IPNet, ipNet6LLA net.IPNet, ipNet6GUA net.IPNet, err error) {

	all, err := net.Interfaces()
	for _, v := range all {
		log.Print("interface name ", v.Name, v.HardwareAddr.String())
	}

	ifi, err = net.InterfaceByName(nic)
	if err != nil {
		return nil, net.IPNet{}, net.IPNet{}, net.IPNet{}, err
	}

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
			ipNet4 = net.IPNet{IP: ip.To4(), Mask: ipNet.Mask}
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

	return ifi, ipNet4, ipNet6LLA, ipNet6GUA, nil
}

const (
	file  = "/proc/net/route"
	line  = 1    // line containing the gateway addr. (first line: 0)
	sep   = "\t" // field separator
	field = 2    // field containing hex gateway address (first field: 0)
)

// GetLinuxDefaultGateway read the default gateway from linux route file
//
// file: /proc/net/route file:
//   Iface   Destination Gateway     Flags   RefCnt  Use Metric  Mask
//   eth0    00000000    C900A8C0    0003    0   0   100 00000000    0   00
//   eth0    0000A8C0    00000000    0001    0   0   100 00FFFFFF    0   00
//
func GetLinuxDefaultGateway() (gw net.IP, err error) {

	file, err := os.Open(file)
	if err != nil {
		return net.IPv4zero, err
	}
	defer file.Close()

	ipd32 := net.IP{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		// jump to line containing the gateway address
		for i := 0; i < line; i++ {
			scanner.Scan()
		}

		// get field containing gateway address
		tokens := strings.Split(scanner.Text(), sep)
		gatewayHex := "0x" + tokens[field]

		// cast hex address to uint32
		d, _ := strconv.ParseInt(gatewayHex, 0, 64)
		d32 := uint32(d)

		// make net.IP address from uint32
		ipd32 = make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipd32, d32)
		fmt.Printf("NIC default gateway is %T --> %[1]v\n", ipd32)

		// format net.IP to dotted ipV4 string
		//ip := net.IP(ipd32).String()
		//fmt.Printf("%T --> %[1]v\n", ip)

		// exit scanner
		break
	}
	return ipd32, nil
}
