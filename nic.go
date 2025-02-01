package packet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// NICInfo stores the network interface info
type NICInfo struct {
	IFI          *net.Interface
	HomeLAN4     netip.Prefix // IPv4: home LAN netmask
	HostAddr4    Addr         // IPv4: host MAC and IPv4
	RouterAddr4  Addr         // IPv4: router MAC and IPv4
	HostLLA      netip.Prefix // IPv6: host LLA
	HostGUA      netip.Prefix // IPv6: host GUA
	RouterLLA    netip.Prefix // IPv6: router LLA
	RouterGUA    netip.Prefix // IPv6: router GUA
	RouterPrefix net.IP       // IPv6: router prefix
}

func (e NICInfo) String() string {
	return fmt.Sprintf("mac=%s homeLAN=%s hostip4=%s lla=%s gua=%s routerIP4=%s routerMAC=%s", e.HostAddr4.MAC, e.HomeLAN4, e.HostAddr4.IP, e.HostLLA, e.HostGUA, e.RouterAddr4.IP, e.RouterAddr4.MAC)
}

// CopyIP simply copies the IP to a new buffer
// Always return len 16 - using go internal 16 bytes for ipv4
func CopyIP(srcIP net.IP) net.IP {
	if len(srcIP) == 4 {
		return srcIP.To16() // this will copy to a new 16 len buffer
	}
	ip := make(net.IP, len(srcIP))
	copy(ip, srcIP)
	return ip
}

// CopyMAC simply copies a mac address to a new buffer with the same len
func CopyMAC(srcMAC net.HardwareAddr) net.HardwareAddr {
	mac := make(net.HardwareAddr, len(srcMAC))
	copy(mac, srcMAC)
	return mac
}

// CopyBytes simply copies a mac address to a new buffer with the same len
func CopyBytes(b []byte) []byte {
	bb := make([]byte, len(b))
	copy(bb, b)
	return bb
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
		// ip, ipNet, err := net.ParseCIDR(addrs[i].String())
		ip, err := netip.ParsePrefix(addrs[i].String())
		if err != nil {
			log.Printf("NIC cannot parse IP %s error %s ", addrs[i].String(), err)
			continue
		}

		if ip.Addr().Is4() && ip.Addr().IsGlobalUnicast() {
			info.HostAddr4.IP = ip.Addr()
			info.HomeLAN4 = ip.Masked()
		}
		if ip.Addr().Is6() {
			if ip.Addr().IsLinkLocalUnicast() {
				info.HostLLA = ip
			}
			if ip.Addr().IsGlobalUnicast() {
				info.HostGUA = ip
			}
		}
	}

	if !info.HostAddr4.IP.IsValid() || info.HostAddr4.IP.IsUnspecified() {
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
	if defaultIP := defaultOutboundIP(); info.HostAddr4.IP != defaultIP {
		Logger.Msg("warning host IP is different than default outbound IP").IP("hostIP", info.HostAddr4.IP).IP("defaultIP", defaultIP).Write()
	}

	defaultGW, err := GetIP4DefaultGatewayAddr(nic)
	if err != nil {
		return nil, err
	}
	info.RouterAddr4 = Addr{MAC: defaultGW.MAC, IP: defaultGW.IP}
	info.HostAddr4 = Addr{MAC: info.IFI.HardwareAddr, IP: info.HostAddr4.IP}
	return info, nil
}

// defaultOutboundIP return the preferred outbound ip
func defaultOutboundIP() netip.Addr {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return netip.Addr{}
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip, _ := netip.AddrFromSlice(localAddr.IP)

	return ip
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
func GetLinuxDefaultGateway() (gw netip.Addr, err error) {
	file, err := os.Open(file)
	if err != nil {
		return netip.Addr{}, err
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
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], d32)
		gw = netip.AddrFrom4(buf)
		if gw.IsUnspecified() {
			return netip.Addr{}, ErrInvalidIP
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
		ip, err := netip.ParseAddr(tokens[0])
		if err != nil || ip.IsUnspecified() {
			fmt.Println("raw: error in loadARPProcTable - invalid IP", tokens, err)
			continue
		}
		mac, err := net.ParseMAC(tokens[3])
		if err != nil || bytes.Equal(mac, net.HardwareAddr{0, 0, 0, 0, 0, 0}) || bytes.Equal(mac, net.HardwareAddr{}) {
			// local IP has entry "192.168.0.129 0x1 0x0 00:00:00:00:00:00 * eth0"
			if Logger.IsDebug() {
				fmt.Println("raw: error in loadARPProcTable - invalid MAC", tokens)
			}
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
				if v.IP == addr.IP {
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

func EnableIP4Forwarding(nic string) error {
	// enable ip_forward
	// sudo echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
	proc := fmt.Sprintf("/proc/sys/net/ipv4/ip_forward")
	if err := ioutil.WriteFile(proc, []byte{'1'}, os.ModePerm); err != nil {
		return fmt.Errorf("failed to set %s: %w", proc, err)
	}
	return nil
}

// ExecPing executes an ICMP ping to the given IP.
// Equivalent to running: /usr/bin/ping -W 1 -i 0.2 -c 1
//
// This is usefull when engine is not yet running and you need to populate the local arp/ndp cache
// If passing an IPv6 LLA, then must pass the scope as in "fe80::1%eth0"
func ExecPing(ip string) (err error) {
	start := time.Now()

	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return fmt.Errorf("resolve ip addr: %w", err)
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("icmp listen packet: %w", err)
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("HELLO-NETFITER"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("icmp marshal: %w", err)
	}

	deadline := start.Add(time.Second)
	period := 200 * time.Millisecond
	nextWrite := start.Add(period)

	for time.Now().Before(deadline) {
		// set next write deadline
		conn.SetDeadline(nextWrite)
		nextWrite = nextWrite.Add(period)
		if nextWrite.After(deadline) {
			nextWrite = deadline
		}

		// send ping
		if _, err := conn.WriteTo(msgBytes, dst); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				// timeout, write next ping
				continue
			}
			return fmt.Errorf("icmp write: %w", err)
		}

		// update seq
		msg.Body.(*icmp.Echo).Seq++
		msgBytes, err = msg.Marshal(nil)
		if err != nil {
			return fmt.Errorf("icmp marshal: %w", err)
		}

		// assume ICMP size < 1500
		reply := make([]byte, 1500)

		// receive reply
		_, _, err := conn.ReadFrom(reply)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				// timeout, write next ping
				continue
			}
			return fmt.Errorf("icmp read: %w", err)
		}

		// success
		return nil
	}

	return fmt.Errorf("ping timeout")
}

func LinuxConfigureInterface(nic string, hostIP netip.Prefix, newIP netip.Prefix, gw netip.Prefix) error {
	if !hostIP.IsValid() || !newIP.IsValid() || !gw.IsValid() {
		return fmt.Errorf("invalid ip prefix")
	}
	if hostIP.Addr() == newIP.Addr() {
		return fmt.Errorf("host ip cannot be the same as new ip")
	}

	// Get a structure describing the network interface.
	localInterface, err := netlink.LinkByName(nic)
	if err != nil {
		return err
	}

	// set new IP and mask - this will automatically set lifetime to forever.
	ipConfig := &netlink.Addr{IPNet: &net.IPNet{IP: newIP.Addr().AsSlice(), Mask: net.CIDRMask(newIP.Bits(), 32)}}
	if err = netlink.AddrAdd(localInterface, ipConfig); err != nil {
		return fmt.Errorf("netlink failed to set new host ip=%s: %w", newIP, err)
	}

	if gw.Addr().Is4() {
		// Setup the default route, so traffic that doesn't hit
		// 192.168.1.(1-255) can be routed.
		if err = netlink.RouteAdd(&netlink.Route{
			Scope:     netlink.SCOPE_UNIVERSE,
			LinkIndex: localInterface.Attrs().Index,
			Dst:       &net.IPNet{IP: gw.Addr().AsSlice(), Mask: net.CIDRMask(gw.Bits(), 32)},
		}); err != nil {
			return err
		}
	}

	// Lastly, bring up the interface.
	if err = netlink.LinkSetUp(localInterface); err != nil {
		return err
	}

	// delete previous IP
	ipConfig = &netlink.Addr{IPNet: &net.IPNet{IP: hostIP.Addr().AsSlice(), Mask: net.CIDRMask(hostIP.Bits(), 32)}}
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
