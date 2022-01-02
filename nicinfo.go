package packet

import (
	"fmt"
	"net"
)

// NICInfo stores the network interface info
type NICInfo struct {
	IFI          *net.Interface
	HomeLAN4     net.IPNet // IPv4: home LAN netmask
	HostAddr4    Addr      // IPv4: host MAC and IPv4
	RouterAddr4  Addr      // IPv4: router MAC and IPv4
	HostLLA      net.IPNet // IPv6: host LLA
	HostGUA      net.IPNet // IPv6: host GUA
	RouterLLA    net.IPNet // IPv6: router LLA
	RouterGUA    net.IPNet // IPv6: router GUA
	RouterPrefix net.IP    // IPv6: router prefix
}

func (e NICInfo) String() string {
	return fmt.Sprintf("mac=%s hostip4=%s lla=%s gua=%s routerIP4=%s routerMAC=%s", e.HostAddr4.MAC, e.HostAddr4.IP, e.HostLLA, e.HostGUA, e.RouterAddr4.IP, e.RouterAddr4.MAC)
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
