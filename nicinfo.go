package packet

import (
	"fmt"
	"net"
)

// NICInfo stores the network interface info
type NICInfo struct {
	IFI *net.Interface

	HostMAC      net.HardwareAddr
	HostIP4      net.IPNet
	HomeLAN4     net.IPNet
	HostLLA      net.IPNet
	HostGUA      net.IPNet
	RouterMAC    net.HardwareAddr
	RouterIP4    net.IPNet
	RouterLLA    net.IPNet
	RouterGUA    net.IPNet
	RouterPrefix net.IP
	HostAddr4    Addr
	RouterAddr4  Addr
}

func (e NICInfo) String() string {
	return fmt.Sprintf("mac=%s hostip4=%s lla=%s gua=%s routerIP4=%s routerMAC=%s", e.HostMAC, e.HostIP4, e.HostLLA, e.HostGUA, e.RouterIP4, e.RouterMAC)
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
