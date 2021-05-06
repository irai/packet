package icmp4

import (
	"fmt"
	"syscall"

	"github.com/irai/packet/model"
)

func (h *Handler) sendPacket(srcAddr model.Addr, dstAddr model.Addr, p model.ICMP4) (err error) {
	ether := model.Ether(make([]byte, model.EthMaxSize)) // Ping is called many times concurrently by client

	ether = model.EtherMarshalBinary(ether, syscall.ETH_P_IP, srcAddr.MAC, dstAddr.MAC)
	ip4 := model.IP4MarshalBinary(ether.Payload(), 50, srcAddr.IP, dstAddr.IP)
	if ip4, err = ip4.AppendPayload(p, syscall.IPPROTO_ICMP); err != nil {
		return err
	}

	if ether, err = ether.SetPayload(ip4); err != nil {
		return err
	}
	if dstAddr.MAC == nil {
		dstAddr.MAC = model.Eth4AllNodesMulticast
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

/***
// PING send a standalone echo packet in a new connection
func PING(dstAddr model.Addr) error {

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
