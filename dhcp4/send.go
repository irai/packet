package dhcp4

import (
	"fmt"
	"net"
	"syscall"

	"github.com/irai/packet"
)

func sendDHCP4Packet(conn net.PacketConn, srcAddr packet.Addr, dstAddr packet.Addr, p DHCP4) (err error) {
	ether := packet.Ether(make([]byte, packet.EthMaxSize))
	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, srcAddr.MAC, dstAddr.MAC)
	ip4 := packet.IP4MarshalBinary(ether.Payload(), 50, srcAddr.IP, dstAddr.IP)
	udp := packet.UDPMarshalBinary(ip4.Payload(), srcAddr.Port, dstAddr.Port)
	udp, err = udp.AppendPayload(p)
	if err != nil {
		return err
	}
	ip4 = ip4.SetPayload(udp, syscall.IPPROTO_UDP)

	if ether, err = ether.SetPayload(ip4); err != nil {
		return err
	}

	// fmt.Printf("dhcp4: DEBUG: send packet %s %s\n", dstAddr, p)

	if _, err := conn.WriteTo(ether, &dstAddr); err != nil {
		fmt.Println("icmp failed to write ", err)
		return err
	}

	return nil
}

/***
// PING send a standalone echo packet in a new connection
func PING(dstAddr packet.Addr) error {

	c, err := net.ListenPacket("ip4:1", "0.0.0.0") // ICMP for IPv4
	if err != nil {
		log.Error("icmp error in listen packet: ", err)
		return err
	}
	defer c.Close()

	r, err := ipv4.NewRawConn(c)
	if err != nil {
		log.Error("icmp error in newrawconn: ", err)
		return err
	}
	c, err := net.ListenPacket("ip4:1", "0.0.0.0") // ICMP for IPv4
	if err != nil {
		log.Error("icmp error in listen packet: ", err)
		return err
	}
	defer c.Close()

	if err := c.WriteTo(iph, p, nil); err != nil {
		log.Error("icmp failed to write ", err)
		return err
	}

	return nil
}
	***/
