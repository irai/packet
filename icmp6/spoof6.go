package icmp6

import (
	"fmt"
	"net"
	"time"

	"github.com/irai/packet"
)

// StartHunt implements packet processor interface
func (h *Handler) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Debug {
		fmt.Printf("icmp6 : force neighbor spoof %s", addr)
	}
	h.Lock()
	if h.huntList.Index(addr.MAC) != -1 {
		h.Unlock()
		return packet.StageHunt, nil
	}
	h.huntList.Add(addr)
	h.Unlock()

	ip := net.ParseIP("fe80::ce32:e5ff:fe0e:67f4") // my home router
	fmt.Println("icmp6 : FIXME ROUTER IP LLA IS HARDCODED")
	srcAddr := packet.Addr{IP: ip, MAC: h.engine.NICInfo.HostMAC}
	go h.spoofLoop(srcAddr, addr)

	return packet.StageHunt, nil
}

// StopHunt implements PacketProcessor interface
func (h *Handler) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Debug {
		fmt.Printf("icmp6 : stop neighbor spoof %s", addr)
	}
	h.Lock()
	if h.huntList.Index(addr.MAC) == -1 {
		return packet.StageNormal, nil
	}
	h.huntList.Del(addr)
	h.Unlock()

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
	fmt.Printf("icmp6 : na attack ip=%s time=%v", dstAddr.IP, startTime)
	for {
		h.Lock()
		if h.huntList.Index(dstAddr.MAC) == -1 || h.closed {
			h.Unlock()
			fmt.Printf("icmp6 : attack end ip=%s repeat=%v duration=%v", dstAddr.IP, nTimes, time.Since(startTime))
			return
		}
		list := []packet.Addr{}
		for _, router := range h.LANRouters {
			list = append(list, router.Addr)
		}
		h.Unlock()

		for _, addr := range list {
			srcAddr.IP = addr.IP
			if err := h.SendNeighborAdvertisement(srcAddr, dstAddr); err != nil {
				fmt.Println("icmp6 : error sending na ", err)
			}

			if nTimes%16 == 0 {
				fmt.Printf("icmp6 attack src %s dst %s repeat=%v duration=%v", srcAddr, dstAddr, nTimes, time.Since(startTime))
			}
			nTimes++
		}

		select {
		case <-h.closeChan:
		case <-ticker:
		}
	}
}
