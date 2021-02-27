package icmp6

import (
	"fmt"
	"net"
	"time"

	"log"

	"github.com/irai/packet/raw"
)

// startHunt performs the following:
func (h *Handler) startHunt(mac net.HardwareAddr) error {
	if Debug {
		log.Printf("icmp6 force neighbor spoof mac=%s", mac)
	}

	h.setHandler.Add(mac)
	go h.spoofLoop(mac)
	return nil
}

// stopHunt terminate the hunting process
func (h *Handler) stopHunt(mac net.HardwareAddr) error {
	if Debug {
		log.Printf("icmp6 stop neighbor spoof mac=%s", mac)
	}
	h.setHandler.Del(mac) // will exit the goroutine

	return nil
}

// spoofLoop attacks the client with ARP attacks
//
// It will continuously send a number of ARP packets to client:
//   1. spoof the client arp table to send router packets to us
//   2. optionally, claim the ownership of the IP to force client to change IP or go offline
//
func (h *Handler) spoofLoop(mac net.HardwareAddr) {

	// 4 second re-do seem to be adequate;
	ticker := time.NewTicker(time.Second * 4).C
	startTime := time.Now()
	nTimes := 0
	log.Printf("icmp6 na attack mac=%s time=%v", mac, startTime)
	for {
		if h.setHandler.Index(mac) == -1 {
			log.Printf("icmp6 na attack end mac=%s time=%v", mac, time.Since(startTime))
			return
		}
		list := h.LANHosts.FindMAC(mac)
		if len(list) == 0 {
			log.Printf("icmp6 empty list in na attack mac=%s time=%v. goroutine terminated.", mac, time.Since(startTime))
			return
		}

		// Send NA to any IPv6 IP associated with mac
		for _, v := range list {
			if raw.IsIP6(v.IP) && v.IP.IsLinkLocalUnicast() {
				if err := h.SendNeighborAdvertisement(raw.IP6DefaultRouter, raw.Addr{MAC: v.MAC, IP: v.IP}); err != nil {
					fmt.Println("icmp6 error sending na ", err)
				}
			}
		}

		if nTimes%16 == 0 {
			log.Printf("icmp6 attack client=%s repeat=%v duration=%v", mac, nTimes, time.Now().Sub(startTime))
		}
		nTimes++

		select {
		case <-ticker:
		}
	}
}
