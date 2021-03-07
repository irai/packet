package icmp6

import (
	"fmt"
	"net"
	"time"

	"log"

	"github.com/irai/packet"
)

// startHunt performs the following:
func (h *Handler) startHunt(ip net.IP) error {
	if Debug {
		log.Printf("icmp6 force neighbor spoof mac=%s", ip)
	}
	host := h.engine.FindIP(ip)
	if host == nil || host.HuntStageIP6 != packet.StageHunt || !packet.IsIP6(host.IP) {
		fmt.Println("icmp6: invalid call to startHuntIP", host)
		return packet.ErrInvalidIP4
	}

	go h.spoofLoop(ip)
	return nil
}

// stopHunt terminate the hunting process
func (h *Handler) stopHunt(ip net.IP) error {
	if Debug {
		log.Printf("icmp6 stop neighbor spoof mac=%s", ip)
	}
	host := h.engine.FindIP(ip)
	if host != nil && (host.HuntStageIP6 == packet.StageHunt || !packet.IsIP6(host.IP)) {
		fmt.Println("invalid call to stopHuntIP", host)
	}

	return nil
}

// spoofLoop attacks the client with ARP attacks
//
// It will continuously send a number of ARP packets to client:
//   1. spoof the client arp table to send router packets to us
//   2. optionally, claim the ownership of the IP to force client to change IP or go offline
//
func (h *Handler) spoofLoop(ip net.IP) {

	// 4 second re-do seem to be adequate;
	ticker := time.NewTicker(time.Second * 4).C
	startTime := time.Now()
	nTimes := 0
	log.Printf("icmp6: na attack ip=%s time=%v", ip, startTime)
	for {
		h.engine.Lock()
		host := h.engine.FindIPNoLock(ip) // will lock/unlock engine
		if host == nil || host.HuntStageIP6 != packet.StageHunt || h.closed {
			h.engine.Unlock()
			log.Printf("icmp6: attack end ip=%s repeat=%v duration=%v", ip, nTimes, time.Now().Sub(startTime))
			return
		}
		mac := host.MAC
		h.engine.Unlock()

		// Send NA to any IPv6 IP associated with mac
		if packet.IsIP6(ip) && ip.IsLinkLocalUnicast() {
			if err := h.SendNeighborAdvertisement(packet.IP6DefaultRouter, packet.Addr{MAC: mac, IP: ip}); err != nil {
				fmt.Println("icmp6: error sending na ", err)
			}
		}

		if nTimes%16 == 0 {
			log.Printf("icmp6 attack ip=%s mac=%s repeat=%v duration=%v", ip, mac, nTimes, time.Now().Sub(startTime))
		}
		nTimes++

		select {
		case <-h.closeChan:
		case <-ticker:
		}
	}
}
