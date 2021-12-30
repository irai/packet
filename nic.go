package packet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/irai/packet/fastlog"
	"github.com/vishvananda/netlink"
)

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

		if ip.To4() != nil && ip.IsGlobalUnicast() {
			info.HostIP4 = net.IPNet{IP: ip.To4(), Mask: ipNet.Mask}
		}
		if ip.To16() != nil && ip.To4() == nil {
			if ip.IsLinkLocalUnicast() {
				info.HostLLA = net.IPNet{IP: ip, Mask: ipNet.Mask}
			}
			if ip.IsGlobalUnicast() {
				info.HostGUA = net.IPNet{IP: ip, Mask: ipNet.Mask}
			}
		}
	}

	if info.HostIP4.IP == nil || info.HostIP4.IP.IsUnspecified() {
		return nil, fmt.Errorf("ipv4 not found on interface")
	}

	// Print warning if nic has more than one IPv4 and our chosen IP is not the default.
	//
	// The following "ip addrs" output is possible on linuxi if dhcpclient is running:
	//
	//   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
	//   link/ether 02:42:15:e6:10:08 brd ff:ff:ff:ff:ff:ff
	//   inet 192.168.0.107/24 brd 192.168.0.255 scope global dynamic eth0
	//      valid_lft 86208sec preferred_lft 86208sec
	//   inet 192.168.0.129/24 brd 192.168.0.255 scope global secondary eth0
	//      valid_lft forever preferred_lft forever
	if defaultIP := defaultOutboundIP(); !info.HostIP4.IP.Equal(defaultIP) {
		fastlog.NewLine(module, "warning host IP is different than default outbound IP").IP("hostIP", info.HostIP4.IP).IP("defaultIP", defaultIP).Write()
	}

	defaultGW, err := GetIP4DefaultGatewayAddr(nic)
	if err != nil {
		return nil, err
	}
	info.RouterIP4 = net.IPNet{IP: defaultGW.IP.To4(), Mask: info.HostIP4.Mask}
	info.RouterMAC = defaultGW.MAC
	info.HomeLAN4 = net.IPNet{IP: info.HostIP4.IP.Mask(info.HostIP4.Mask).To4(), Mask: info.HostIP4.Mask}
	info.HostMAC = info.IFI.HardwareAddr
	info.RouterAddr4 = Addr{MAC: info.RouterMAC, IP: info.RouterIP4.IP}
	info.HostAddr4 = Addr{MAC: info.HostMAC, IP: info.HostIP4.IP}
	return info, nil
}

// defaultOutboundIP return the preferred outbound ip
func defaultOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

const (
	file = "/proc/net/route"
	line = 1    // line containing the gateway addr. (first line: 0)
	sep  = "\t" // field separator
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

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		// jump to line containing the gateway address
		for i := 0; i < line; i++ {
			scanner.Scan()
		}

		// get field containing gateway address
		tokens := strings.Split(scanner.Text(), sep)
		gatewayHex := "0x" + tokens[2] // field containing hex gateway address (first field: 0)

		d, _ := strconv.ParseInt(gatewayHex, 0, 64)
		d32 := uint32(d)
		gw = make(net.IP, 4)
		binary.LittleEndian.PutUint32(gw, d32)
		if gw.IsUnspecified() {
			return nil, ErrInvalidIP
		}
	}
	return gw, nil
}

// LoadLinuxARPTable read arp entries from linux proc file
//
// /proc/net/arp format:
//   IP address       HW type     Flags       HW address            Mask     Device
//   192.168.0.1      0x1         0x2         20:0c:c8:23:f7:1a     *        eth0
//   192.168.0.4      0x1         0x2         4c:bb:58:f4:b2:d7     *        eth0
//   192.168.0.5      0x1         0x2         84:b1:53:ea:1f:40     *        eth0
//
func LoadLinuxARPTable(nic string) (list []Addr, err error) {
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
		list = append(list, Addr{MAC: mac, IP: ip})
	}

	return list, nil
}

// GetIP4DefaultGatewayAddr return the IP4 default gatewy for nic
func GetIP4DefaultGatewayAddr(nic string) (addr Addr, err error) {

	if addr.IP, err = GetLinuxDefaultGateway(); err != nil {
		fmt.Println("error getting router ", err)
		return Addr{}, ErrInvalidIP
	}
	addr.IP = addr.IP.To4()

	// Try 3 times to read arp table
	// This is required if we just reset the interface and the arp table is nil
	var arpList []Addr
	for i := 0; i < 3; i++ {
		ExecPing(addr.IP.String()) // ping to populate arp table
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
		return Addr{}, fmt.Errorf("default gw mac not found on interface")
	}

	return addr, nil
}

// ExecPing execute /usr/bin/ping
//
// This is usefull when engine is not yet running and you need to populate the local arp/ndp cache
// If passing an IPv6 LLA, then must pass the scope as in "fe80::1%eth0"
func ExecPing(ip string) (err error) {
	// -w deadline - wait 1 second
	// -i frequency - one request each 0,2 seconds
	// -c count - how many replies to receive before returning (in conjuction with -w)
	cmd := exec.Command("/usr/bin/ping", ip, "-w", "1", "-i", "0.2", "-c", "1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		// fmt.Printf("packet: failed to ping ip=%s error=%s\n", ip, err)
		return err
	}
	// fmt.Printf("ping: %q\n", stdout.String())
	// fmt.Printf("errs: %q\n", stderr.String())
	return err
}

func LinuxConfigureInterface(nic string, hostIP *net.IPNet, newIP *net.IPNet, gw *net.IPNet) error {
	if hostIP.IP.Equal(newIP.IP) {
		return fmt.Errorf("host ip cannot be the same as new ip")
	}

	// Get a structure describing the network interface.
	localInterface, err := netlink.LinkByName(nic)
	if err != nil {
		return err
	}

	// set new IP and mask - this will automatically set lifetime to forever.
	ipConfig := &netlink.Addr{IPNet: newIP}
	if err = netlink.AddrAdd(localInterface, ipConfig); err != nil {
		return fmt.Errorf("netlink failed to set new host ip=%s: %w", newIP, err)
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

	// delete previous IP
	ipConfig = &netlink.Addr{IPNet: hostIP}
	if err = netlink.AddrDel(localInterface, ipConfig); err != nil {
		return fmt.Errorf("netlink failed to delete host ip=%s: %w", hostIP, err)
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
