package engine

import (
	"net"
	"syscall"

	"github.com/irai/packet"
)

var (
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	ip1     = net.IPv4(192, 168, 0, 1)
	ip2     = net.IPv4(192, 168, 0, 2)
	ip3     = net.IPv4(192, 168, 0, 3)
	ip4     = net.IPv4(192, 168, 0, 4)
	ip5     = net.IPv4(192, 168, 0, 5)
	_       = zeroMAC // remove lint warning
	_       = ip1     // remove lint warning
	_       = ip4     // remove lint warning
	_       = ip5     // remove lint warning

	hostMAC   = net.HardwareAddr{0x00, 0x55, 0x55, 0x55, 0x55, 0x55}
	hostIP4   = net.IPv4(192, 168, 0, 129).To4()
	routerMAC = net.HardwareAddr{0x00, 0x66, 0x66, 0x66, 0x66, 0x66}
	routerIP4 = net.IPv4(192, 168, 0, 11).To4()
	homeLAN   = net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}

	mac1 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x05}
	_    = mac3 // remove lint warning
	_    = mac4 // remove lint warning
	_    = mac5 // remove lint warning

	ip6LLA1 = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	// 2001:4479:1d01:2401:7cf2:4f73:f8c1:8b63
	ip6GUA1 = net.IP{0x20, 0x01, 0x44, 0x79, 0x1d, 0x01, 0x24, 0x01, 0x7c, 0xf2, 0x4f, 0x73, 0xf8, 0xc1, 0x00, 0x01}
	ip6GUA2 = net.IP{0x20, 0x01, 0x44, 0x79, 0x1d, 0x01, 0x24, 0x01, 0x7c, 0xf2, 0x4f, 0x73, 0xf8, 0xc1, 0x00, 0x02}
	ip6GUA3 = net.IP{0x20, 0x01, 0x44, 0x79, 0x1d, 0x01, 0x24, 0x01, 0x7c, 0xf2, 0x4f, 0x73, 0xf8, 0xc1, 0x00, 0x03}

	hostAddr   = packet.Addr{MAC: hostMAC, IP: hostIP4}
	routerAddr = packet.Addr{MAC: routerMAC, IP: routerIP4}
)

func newTestHost(session *packet.Session, srcAddr packet.Addr) packet.Frame {
	// create an arp reply packet
	p := make([]byte, packet.EthMaxSize)
	ether := packet.EncodeEther(p, syscall.ETH_P_IP, srcAddr.MAC, packet.EthBroadcast)
	if ip := srcAddr.IP.To4(); ip != nil {
		ip4 := packet.EncodeIP4(ether.Payload(), 255, srcAddr.IP, packet.IP4Broadcast)
		ether, _ = ether.SetPayload(ip4)
	} else {
		ether = packet.EncodeEther(p, syscall.ETH_P_IPV6, srcAddr.MAC, packet.EthBroadcast)
		ip6 := packet.EncodeIP6(ether.Payload(), 255, srcAddr.IP, packet.IP6AllNodesMulticast)
		ether, _ = ether.SetPayload(ip6)
	}
	frame, err := session.Parse(ether)
	if err != nil {
		panic(err)
	}
	if frame.Host == nil {
		panic("invalid nil test host")
	}
	return frame
}
