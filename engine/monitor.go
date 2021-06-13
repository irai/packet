package engine

import (
	"errors"
	"fmt"
	"time"

	"github.com/irai/packet"
)

// lockAndMonitorRoute monitors the default gateway is still pointing to us
func (h *Handler) lockAndMonitorRoute(now time.Time) (err error) {
	table := h.session.GetHosts()
	for _, host := range table {
		host.MACEntry.Row.RLock()
		if host.HuntStage == packet.StageRedirected && host.Addr.IP.To4() != nil {
			addr := packet.Addr{MAC: host.MACEntry.MAC, IP: host.Addr.IP}
			host.MACEntry.Row.RUnlock()
			_, err := h.ICMP4Handler.CheckAddr(addr) // ping host
			if errors.Is(err, packet.ErrNotRedirected) {
				fmt.Printf("packet: ip4 routing NOK %s\n", host)
				// Call stop hunt first to update stage to normal
				if err := h.lockAndStopHunt(host, packet.StageNormal); err != nil {
					fmt.Printf("packet: failed to stop hunt %s error=\"%s\"\n", host, err)
				}
				if err := h.lockAndStartHunt(addr); err != nil {
					fmt.Printf("packet: failed to start hunt %s error=\"%s\"\n", host, err)
				}
			} else {
				if err == nil && packet.Debug {
					fmt.Printf("packet: ip4 routing OK %s\n", host)
				}
			}
			// lock again before loop
			host.MACEntry.Row.RLock()
		}
		host.MACEntry.Row.RUnlock()
	}

	return nil
}

func (h *Handler) minuteChecker(now time.Time) {
	if packet.Debug {
		fmt.Printf("packet: running minute checker %v\n", now)
	}

	// Handlers
	h.ARPHandler.MinuteTicker(now)
	h.ICMP4Handler.MinuteTicker(now)
	h.ICMP6Handler.MinuteTicker(now)
	h.DHCP4Handler.MinuteTicker(now)

	// internal checks
	h.lockAndMonitorRoute(now)

	// received a new "onlink" event
	if h.forceScan {
		h.forceScan = false
		h.ICMP6Handler.PingAll()
	}
	h.purge(now, h.ProbeInterval, h.OfflineDeadline, h.PurgeDeadline)

}

func (h *Handler) minuteLoop() {
	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-ticker.C:
			h.minuteChecker(time.Now())

		case <-h.closeChan:
			return
		}
	}
}
