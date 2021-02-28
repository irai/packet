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

// NICInfo stores the network interface info
type NICInfo struct {
	IFI       *net.Interface
	HostMAC   net.HardwareAddr
	HostIP4   net.IPNet
	RouterIP4 net.IPNet
	HomeLAN4  net.IPNet
	HostLLA   net.IPNet
	HostGUA   net.IPNet
}

func (e NICInfo) String() string {
	return fmt.Sprintf("mac=%s hostip4=%s lla=%s gua=%s router=%s", e.HostMAC, e.HostIP4, e.HostLLA, e.HostGUA, e.RouterIP4)
}

// GetNICInfo returns the interface configuration
//
// TODO: use routing package to identify default router
// https://github.com/google/gopacket/tree/v1.1.19/routing
func GetNICInfo(nic string) (info *NICInfo, err error) {

	info = &NICInfo{}
	info.IFI, err = net.InterfaceByName(nic)
	if err != nil {
		return nil, err
	}

	addrs, err := info.IFI.Addrs()
	if err != nil {
		return nil, err
	}

	for i := range addrs {
		ip, ipNet, err := net.ParseCIDR(addrs[i].String())
		if err != nil {
			log.Printf("NIC cannot parse IP %s error %s ", addrs[i].String(), err)
			continue
		}

		if ipNet.IP.To4() != nil && ipNet.IP.IsGlobalUnicast() {
			info.HostIP4 = net.IPNet{IP: ip.To4(), Mask: ipNet.Mask}
		}
		if ipNet.IP.To16() != nil && ipNet.IP.To4() == nil {
			if ipNet.IP.IsLinkLocalUnicast() {
				info.HostLLA = net.IPNet{IP: ip, Mask: ipNet.Mask}
			}
			if ipNet.IP.IsGlobalUnicast() {
				info.HostGUA = net.IPNet{IP: ip, Mask: ipNet.Mask}
			}
		}
	}

	if info.HostIP4.IP == nil || info.HostIP4.IP.IsUnspecified() {
		return nil, fmt.Errorf("ipv4 not found on interface")
	}

	var router net.IP
	if router, err = GetLinuxDefaultGateway(); err != nil {
		fmt.Println("error getting router ", err)
	}
	info.RouterIP4 = net.IPNet{IP: router.To4(), Mask: info.HostIP4.Mask}
	info.HomeLAN4 = net.IPNet{IP: info.HostIP4.IP.Mask(info.HostIP4.Mask).To4(), Mask: info.HostIP4.Mask}
	info.HostMAC = info.IFI.HardwareAddr
	return info, nil
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
