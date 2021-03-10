package arp

import (
	"fmt"
	"net"
	"time"

	"log"

	"github.com/irai/packet"
)

// StartHunt implements PacketProcessor interface
// Engine must set host.HuntStageIP4 to StageHunt prior to calling this
func (h *Handler) StartHunt(ip net.IP) error {
	host := h.engine.FindIP(ip)
	if host == nil || host.HuntStage != packet.StageHunt || host.IP.To4() == nil {
		fmt.Println("arp: invalid call to startHuntIP", host)
		return packet.ErrInvalidIP
	}
	go h.spoofLoop(ip)
	return nil
}

// StopHunt implements PacketProcessor interface
// Engine must set host.HuntStageIP4 != StageHunt prior to calling this
func (h *Handler) StopHunt(ip net.IP) error {
	host := h.engine.FindIP(ip)
	if host != nil && host.HuntStage == packet.StageHunt {
		fmt.Println("invalid call to stopHuntIP", host)
	}
	return nil
}

// startSpoof performs the following:
//  1. set client state to "hunt" which will continuously spoof the client ARP table
//  2. start spoof goroutine to poison client arp table
//
// client will revert back to "normal" when a new IP is detected for the MAC
func (h *Handler) startSpoof(mac net.HardwareAddr) error {
	if Debug {
		log.Printf("arp start spoof mac=%s", mac)
	}

	for _, v := range h.engine.FindByMAC(mac) {
		if ip := v.IP.To4(); ip != nil {
			go h.spoofLoop(v.IP)
		}
	}
	return nil
}

// stopSpoof terminate the hunting process
func (h *Handler) stopSpoof(mac net.HardwareAddr) error {
	if Debug {
		log.Printf("arp stop spoof mac=%s", mac)
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

	// 4 second re-arp seem to be adequate;
	// Experimented with 300ms but no noticeable improvement other the chatty net.
	ticker := time.NewTicker(time.Second * 4).C
	startTime := time.Now()
	nTimes := 0
	log.Printf("arp attack start ip=%s time=%v", ip, startTime)
	for {
		h.engine.Lock()
		host := h.engine.FindIPNoLock(ip) // will lock/unlock engine
		if host == nil || host.HuntStage != packet.StageHunt || h.closed {
			h.engine.Unlock()
			log.Printf("arp attack end ip=%s repeat=%v duration=%v", ip, nTimes, time.Now().Sub(startTime))
			return
		}
		mac := host.MACEntry.MAC
		h.engine.Unlock()

		// Re-arp target to change router to host so all traffic comes to us
		// i.e. tell target I am 192.168.0.1
		//
		// Use virtual IP as it is guaranteed to not change.
		h.forceSpoof(mac, ip)

		if nTimes%16 == 0 {
			log.Printf("arp attack ip=%s mac=%s repeat=%v duration=%v", ip, mac, nTimes, time.Now().Sub(startTime))
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
func (h *Handler) forceSpoof(mac net.HardwareAddr, ip net.IP) error {

	// Announce to target that we own the router IP
	// This will update the target arp table with our mac
	err := h.announce(mac, h.engine.NICInfo.HostMAC, h.engine.NICInfo.RouterIP4.IP, EthernetBroadcast, 2)
	if err != nil {
		log.Printf("arp error send announcement packet mac=%s ip=%s: %s", mac, ip, err)
		return err
	}

	// Send 3 unsolicited ARP reply; clients may discard this
	for i := 0; i < 2; i++ {
		err = h.reply(mac, h.engine.NICInfo.HostMAC, h.engine.NICInfo.RouterIP4.IP, mac, ip)
		if err != nil {
			log.Printf("arp error spoof client mac=%s ip=%s: %s", mac, ip, err)
			return err
		}
		time.Sleep(time.Millisecond * 10)
	}

	return nil
}

// DONUSEforceAnnouncement send a ARP packets to tell the network we are using the IP.
// NOT used anymore
func (h *Handler) DONUSEforceAnnouncement(dstEther net.HardwareAddr, mac net.HardwareAddr, ip net.IP) error {
	err := h.announce(dstEther, mac, ip, EthernetBroadcast, 4) // many repeats to force client to reaquire IP
	if err != nil {
		log.Printf("arp error send announcement packet mac=%s ip=%s: %s", mac, ip, err)
	}

	// Send gratuitous ARP replies : Log the first one only
	// err = c.Reply(mac, ip, EthernetBroadcast, ip) // Send broadcast gratuitous ARP reply
	err = h.reply(dstEther, mac, ip, EthernetBroadcast, ip) // Send gratuitous ARP reply - unicast to target
	for i := 0; i < 3; i++ {
		if err != nil {
			log.Printf("arp error send gratuitous packet mac=%s ip=%s: %s", mac, ip, err)
		}
		time.Sleep(time.Millisecond * 10)

		// Dont show in log
		err = h.reply(dstEther, mac, ip, EthernetBroadcast, ip) // Send gratuitous ARP reply
	}

	return nil
}
