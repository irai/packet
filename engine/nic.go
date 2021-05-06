package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/irai/packet/icmp4"
	"github.com/irai/packet/model"
	"github.com/vishvananda/netlink"
)

// GetNICInfo returns the interface configuration
//
// TODO: use routing package to identify default router
// https://github.com/google/gopacket/tree/v1.1.19/routing
func GetNICInfo(nic string) (info *model.NICInfo, err error) {

	info = &model.NICInfo{}
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

	defaultGW, err := GetIP4DefaultGatewayAddr(nic)
	if err != nil {
		return nil, err
	}
	info.RouterIP4 = net.IPNet{IP: defaultGW.IP.To4(), Mask: info.HostIP4.Mask}
	info.RouterMAC = defaultGW.MAC
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
		// fmt.Printf("NIC default gateway is %T --> %[1]v\n", ipd32)

		// format net.IP to dotted ipV4 string
		//ip := net.IP(ipd32).String()
		//fmt.Printf("%T --> %[1]v\n", ip)

		// exit scanner
		break
	}
	return ipd32, nil
}

// LoadLinuxARPTable read arp entries from linux proc file
//
// /proc/net/arp format:
//   IP address       HW type     Flags       HW address            Mask     Device
//   192.168.0.1      0x1         0x2         20:0c:c8:23:f7:1a     *        eth0
//   192.168.0.4      0x1         0x2         4c:bb:58:f4:b2:d7     *        eth0
//   192.168.0.5      0x1         0x2         84:b1:53:ea:1f:40     *        eth0
//
func LoadLinuxARPTable(nic string) (list []model.Addr, err error) {
	const name = "/proc/net/arp"

	file, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open proc file=%s: %w ", name, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip first row with fields description

	for scanner.Scan() {
		tokens := strings.Fields(scanner.Text())
		if len(tokens) < 6 {
			fmt.Println("raw: error in loadARPProcTable - missing fields", tokens)
			continue
		}
		if tokens[5] != nic {
			continue
		}
		ip := net.ParseIP(tokens[0]).To4()
		if ip == nil || ip.IsUnspecified() {
			fmt.Println("raw: error in loadARPProcTable - invalid IP", tokens)
			continue
		}
		mac, err := net.ParseMAC(tokens[3])
		if err != nil || bytes.Equal(mac, net.HardwareAddr{0, 0, 0, 0, 0, 0}) || bytes.Equal(mac, net.HardwareAddr{}) {
			fmt.Println("raw: error in loadARPProcTable - invalid MAC", tokens)
			continue
		}
		list = append(list, model.Addr{MAC: mac, IP: ip})
	}

	return list, nil
}

// GetIP4DefaultGatewayAddr return the IP4 default gatewy for nic
func GetIP4DefaultGatewayAddr(nic string) (addr model.Addr, err error) {

	if addr.IP, err = GetLinuxDefaultGateway(); err != nil {
		fmt.Println("error getting router ", err)
		return model.Addr{}, model.ErrInvalidIP
	}
	addr.IP = addr.IP.To4()

	// Try 3 times to read arp table
	// This is required if we just reset the interface and the arp table is nil
	var arpList []model.Addr
	for i := 0; i < 3; i++ {
		icmp4.Ping(addr.IP) // ping to populate arp table
		time.Sleep(time.Millisecond * 15)
		arpList, err = LoadLinuxARPTable(nic)
		if err == nil {
			// search in table; if the arp entry is not yeet complete, the mac will be zero or wont exist
			for _, v := range arpList {
				if v.IP.Equal(addr.IP) {
					addr.MAC = v.MAC
					break
				}
			}
		}
	}
	if addr.MAC == nil {
		return model.Addr{}, fmt.Errorf("default gw mac not found on interface")
	}

	return addr, nil
}

// SegmentLAN will identify a free IP on the opposite half segment from the routerIP.
// This function will also test if the chosen IP is available before returning.
func SegmentLAN(nic string, hostIP net.IPNet, routerIP net.IPNet) (netfilterIP net.IPNet, err error) {

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
	case net169.Contains(routerIP.IP):
	case net172.Contains(routerIP.IP):
	case net192.Contains(routerIP.IP):
	case net10.Contains(routerIP.IP):

	default:
		fmt.Printf("packet: error unexpected IP network %+v\n", routerIP)
	}

	// Ignore large networks: we only need 128 hosts for our DHCP -
	// 128 hosts should be enought for all homes
	n, _ := routerIP.Mask.Size()
	if n < 24 {
		n = 24
	}

	if n > 24 {
		err = fmt.Errorf("network mask too small (less than 8 bits) router %+v", routerIP)
		return netfilterIP, err
	}

	// Set router address for netfilter
	// Router segment will be at the opposite end of the Home segment
	homeRouterIP := routerIP.IP.To4() // make sure we are dealing with 4 bytes
	if homeRouterIP[3] < 128 {
		// 128 to 255 - but don't use network address 0 and broadcast 254
		netfilterIP.IP, err = locateFreeIP(nic, hostIP.IP, homeRouterIP, 129, 254)
	} else {
		// 0 to 127 - but don't use network address 0 and broadcast 127
		netfilterIP.IP, err = locateFreeIP(nic, hostIP.IP, homeRouterIP, 1, 126)
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
	newIP = model.CopyIP(ip).To4()
	for i := start; i <= end; i++ {
		newIP[3] = i // save to variable

		// if host already set for this IP
		if hostIP.Equal(newIP) {
			return newIP, nil
		}

		// ping to populate arp table
		if nic != "" {
			icmp4.Ping(ip) // populate arp table
		}

		// check if arp table has the IP
		arpTable, err := LoadLinuxARPTable(nic)
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

func LinuxConfigureInterface(nic string, ip *net.IPNet, gw *net.IPNet) error {

	// Get a structure describing the network interface.
	localInterface, err := netlink.LinkByName(nic)
	if err != nil {
		return err
	}

	// Give the interface an address of 192.168.1.1, on a
	// network with a 255.255.255.0 mask.
	ipConfig := &netlink.Addr{IPNet: ip}
	if err = netlink.AddrAdd(localInterface, ipConfig); err != nil {
		fmt.Printf("nic: error configuring netlink error=%s\n", err)
		return err
	}

	if gw != nil {
		// Setup the default route, so traffic that doesn't hit
		// 192.168.1.(1-255) can be routed.
		if err = netlink.RouteAdd(&netlink.Route{
			Scope:     netlink.SCOPE_UNIVERSE,
			LinkIndex: localInterface.Attrs().Index,
			// Dst:       &net.IPNet{IP: gatewayIP, Mask: net.CIDRMask(32, 32)},
			Dst: gw,
		}); err != nil {
			return err
		}
	}

	// Lastly, bring up the interface.
	if err = netlink.LinkSetUp(localInterface); err != nil {
		return err
	}
	return nil
}

// ServerIsReacheable attemps to resolve "google.com" using the serverIP.
// It return nil if okay or error if server is unreachable.
func ServerIsReacheable(ctx context.Context, serverIP net.IP) (err error) {
	r := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			// return d.DialContext(ctx, "udp", "8.8.4.4:53")
			return d.DialContext(ctx, "udp", fmt.Sprintf("%s:53", serverIP))
		},
	}

	ctx2, cancel := context.WithTimeout(context.Background(), time.Second*5)
	if ctx == nil {
		ctx = ctx2
	}
	_, err = r.LookupHost(ctx, "google.com")
	cancel()

	return err
}
