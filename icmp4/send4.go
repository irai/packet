package icmp4

import (
	"fmt"
	"syscall"

	"github.com/irai/packet"
)

func (h *Handler) sendPacket(srcAddr packet.Addr, dstAddr packet.Addr, p packet.ICMP4) (err error) {
	ether := packet.Ether(make([]byte, packet.EthMaxSize)) // Ping is called many times concurrently by client

	ether = packet.EtherMarshalBinary(ether, syscall.ETH_P_IP, srcAddr.MAC, dstAddr.MAC)
	ip4 := packet.IP4MarshalBinary(ether.Payload(), 50, srcAddr.IP, dstAddr.IP)
	if ip4, err = ip4.AppendPayload(p, syscall.IPPROTO_ICMP); err != nil {
		return err
	}

	if ether, err = ether.SetPayload(ip4); err != nil {
		return err
	}
	if dstAddr.MAC == nil {
		dstAddr.MAC = packet.Eth4AllNodesMulticast
	}

	if Debug {
		fmt.Printf("icmp4: send %s\n", p)
	}
	if _, err := h.session.Conn.WriteTo(ether, &dstAddr); err != nil {
		fmt.Println("icmp failed to write ", err)
		return err
	}

	return nil
}
