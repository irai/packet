package packet

import (
	"fmt"
	"net"
)

// NICInfo stores the network interface info
type NICInfo struct {
	IFI *net.Interface

	HostMAC  net.HardwareAddr
	HostIP4  net.IPNet
	HomeLAN4 net.IPNet
	HostLLA  net.IPNet
	HostGUA  net.IPNet

	RouterMAC    net.HardwareAddr
	RouterIP4    net.IPNet
	RouterLLA    net.IPNet
	RouterGUA    net.IPNet
	RouterPrefix net.IP
}

func (e NICInfo) String() string {
	return fmt.Sprintf("mac=%s hostip4=%s lla=%s gua=%s routerIP4=%s routerMAC=%s", e.HostMAC, e.HostIP4, e.HostLLA, e.HostGUA, e.RouterIP4, e.RouterMAC)
}
