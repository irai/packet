package icmp6

import (
	"fmt"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/model"
)

// StartHunt implements packet processor interface
func (h *ICMP6Handler) StartHunt(addr model.Addr) (packet.HuntStage, error) {
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

	go h.spoofLoop(addr)

	return packet.StageHunt, nil
}

// StopHunt implements PacketProcessor interface
func (h *ICMP6Handler) StopHunt(addr model.Addr) (packet.HuntStage, error) {
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
func (h *ICMP6Handler) spoofLoop(dstAddr model.Addr) {
	// 4 second re-do seem to be adequate;
	ticker := time.NewTicker(time.Second * 4).C
	startTime := time.Now()
	nTimes := 0
	fmt.Printf("icmp6 : na attack ip=%s time=%v", dstAddr.IP, startTime)
	for {
		h.Lock()

		// Attack when we have the router LLA only
		if h.Router != nil {
			srcAddr := model.Addr{IP: h.Router.Addr.IP, MAC: h.engine.NICInfo.HostMAC}
			if h.huntList.Index(dstAddr.MAC) == -1 || h.closed {
				h.Unlock()
				fmt.Printf("icmp6 : attack end ip=%s repeat=%v duration=%v", dstAddr.IP, nTimes, time.Since(startTime))
				return
			}
			list := []model.Addr{}
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
					fmt.Printf("icmp6 : attack src %s dst %s repeat=%v duration=%v", srcAddr, dstAddr, nTimes, time.Since(startTime))
				}
				nTimes++
			}
		} else {
			h.Unlock()
			if nTimes%16 == 0 {
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
