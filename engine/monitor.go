package engine

import (
	"errors"
	"fmt"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/dns"
	"github.com/irai/packet/fastlog"
)

// lockAndMonitorRoute monitors the default gateway is still pointing to us
func (h *Handler) lockAndMonitorRoute(now time.Time) (err error) {
	table := h.session.GetHosts()
	for _, host := range table {
		host.MACEntry.Row.RLock()
		addr := host.Addr

		if host.Addr.IP.To4() == nil { // Ignore if not IP4
			host.MACEntry.Row.RUnlock()
			continue
		}
		if host.HuntStage != packet.StageRedirected { // ignore if are we hunting this host
			if packet.Debug && host.HuntStage == packet.StageHunt {
				fastlog.NewLine(module, "ip4 routing ignore host in hunt stage").Struct(addr).Write()
			}
			host.MACEntry.Row.RUnlock()
			continue
		}

		host.MACEntry.Row.RUnlock()

		_, err := h.ICMP4Handler.CheckAddr(addr) // ping host
		if err == nil {
			if packet.Debug {
				fastlog.NewLine(module, "ip4 routing OK").Struct(addr).Write()
			}
			continue
		}
		if errors.Is(err, packet.ErrNotRedirected) {
			fastlog.NewLine(module, "ip4 routing NOK").Struct(addr).Write()
			// Call stop hunt first to update stage to normal
			if err := h.lockAndStopHunt(host, packet.StageNormal); err != nil {
				fastlog.NewLine(module, "ip4 routing failed to stop hunt").Struct(addr).Error(err).Write()
			}
			if err := h.lockAndStartHunt(addr); err != nil {
				fastlog.NewLine(module, "ip4 routing failed to start hunt").Struct(addr).Error(err).Write()
			}
		}
	}

	return nil
}

func (h *Handler) minuteChecker(now time.Time) {
	if packet.Debug {
		fmt.Printf("packet: running 1 minute checker %v\n", now)
	}

	// ARP Handler - will global lock session
	if err := h.ARPHandler.MinuteTicker(now); err != nil {
		fmt.Printf("packet: error in arp minute checker err=\"%s\"\n", err)
	}

	// ICMP4 Handler - no lock
	h.ICMP4Handler.MinuteTicker(now)

	// ICMP6 - no lock
	if err := h.ICMP6Handler.MinuteTicker(now); err != nil {
		fmt.Printf("packet: error in icmp6 minute checker err=\"%s\"\n", err)
	}

	// no lock
	h.DHCP4Handler.MinuteTicker(now)

	// internal checks
	h.lockAndMonitorRoute(now)

	h.purge(now, h.ProbeInterval, h.OfflineDeadline, h.PurgeDeadline)

}

/**
func (h *Handler) threeMinuteChecker(now time.Time) {
	if packet.Debug {
		fmt.Printf("packet: running 3 minute checker %v\n", now)
	}
}
**/

// hourly runs every 60 minutes
func (h *Handler) hourly(now time.Time) {
	fmt.Printf("packet: running hourly checker %v\n", now)
	// send MDNS service discovery
	if err := h.DNSHandler.SendMDNSQuery(dns.MDNSServiceDiscovery); err != nil {
		fmt.Printf("engine: error in hourly dns query %s\n", err)
	}

	// send SSDP service search
	if err := h.DNSHandler.SendSSDPSearch(); err != nil {
		fmt.Printf("engine: error in hourly dns query %s\n", err)
	}
}

func (h *Handler) minuteLoop() {
	ticker := time.NewTicker(time.Minute)
	counter := 60
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			counter--

			go h.minuteChecker(now)

			/**
			if (counter % 3) == 0 { // three minutes
				// run in goroutine
				go h.threeMinuteChecker(now)
			}
			**/

			if counter <= 0 {
				counter = 60
				// run in goroutine
				go h.hourly(now)
			}
		case <-h.closeChan:
			fmt.Println("engine: minute loop goroutine ended")
			return
		}
	}
}
