package dhcp4

import (
	"fmt"
	"net"
	"syscall"

	"github.com/irai/packet"
)

func sendDHCP4Packet(conn net.PacketConn, srcAddr packet.Addr, dstAddr packet.Addr, p packet.DHCP4) (err error) {
	b := packet.EtherBufferPool.Get().(*[packet.EthMaxSize]byte)
	defer packet.EtherBufferPool.Put(b)
	ether := packet.Ether(b[0:])
	ether = packet.EncodeEther(ether, syscall.ETH_P_IP, srcAddr.MAC, dstAddr.MAC)
	ip4 := packet.EncodeIP4(ether.Payload(), 50, srcAddr.IP, dstAddr.IP)
	udp := packet.EncodeUDP(ip4.Payload(), srcAddr.Port, dstAddr.Port)
	udp, err = udp.AppendPayload(p)
	if err != nil {
		return err
	}
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)

	if ether, err = ether.SetPayload(ip4); err != nil {
		return err
	}

	if _, err := conn.WriteTo(ether, &dstAddr); err != nil {
		fmt.Println("icmp failed to write ", err)
		return err
	}

	return nil
}
