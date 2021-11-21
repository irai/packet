package engine

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/dns"
	"github.com/irai/packet/fastlog"
)

// lockAndMonitorRoute monitors the default gateway is still pointing to us
func (h *Handler) lockAndMonitorRoute(now time.Time) (err error) {
	table := h.session.GetHosts()
	for _, host := range table {
		macEntry := host.MACEntry // keep a copy in case host.MACEntry changes (i.e. merging macs)

		macEntry.Row.RLock()
		addr := host.Addr

		if host.Addr.IP.To4() == nil { // Ignore if not IP4
			macEntry.Row.RUnlock()
			continue
		}
		if host.HuntStage != packet.StageRedirected { // ignore if are we hunting this host
			if packet.Debug && host.HuntStage == packet.StageHunt {
				fastlog.NewLine(module, "ip4 routing ignore host in hunt stage").Struct(addr).Write()
			}
			macEntry.Row.RUnlock()
			continue
		}

		macEntry.Row.RUnlock()

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
		fastlog.NewLine(module, "running 1 minute checker").Time("now", now).Write()
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

// purge set entries offline and subsequently delete them if no more traffic received.
// The funcion is called each minute by the minute goroutine.
func (h *Handler) purge(now time.Time, probeDur time.Duration, offlineDur time.Duration, purgeDur time.Duration) error {
	probeCutoff := now.Add(probeDur * -1)     // Check entries last updated before this time
	offlineCutoff := now.Add(offlineDur * -1) // Mark offline entries last updated before this time
	deleteCutoff := now.Add(purgeDur * -1)    // Delete entries that have not responded in last hour

	purge := make([]net.IP, 0, 16)
	probe := make([]packet.Addr, 0, 16)
	offline := make([]*packet.Host, 0, 16)

	// h.session.GlobalRLock()
	table := h.session.GetHosts()
	for _, e := range table {
		e.MACEntry.Row.RLock()

		// Delete from table if the device is offline and was not seen for the last hour
		if !e.Online && e.LastSeen.Before(deleteCutoff) {
			purge = append(purge, e.Addr.IP)
			e.MACEntry.Row.RUnlock()
			continue
		}

		// Probe if device not seen recently
		if e.Online && e.LastSeen.Before(probeCutoff) {
			probe = append(probe, e.Addr)
		}

		// Set offline if no updates since the offline deadline
		if e.Online && e.LastSeen.Before(offlineCutoff) {
			offline = append(offline, e)
		}
		e.MACEntry.Row.RUnlock()
	}

	// run probe addr in goroutine as checkaddr ping may take a few seconds to return
	if len(probe) > 0 {
		go func() {
			for _, addr := range probe {
				if ip := addr.IP.To4(); ip != nil {
					h.ARPHandler.CheckAddr(addr)
				} else {
					h.ICMP6Handler.CheckAddr(addr)
				}
			}
		}()
	}

	for _, host := range offline {
		h.session.SetOffline(host) // will lock/unlock row
	}

	// delete after loop because this will change the table
	if len(purge) > 0 {
		for _, v := range purge {
			h.session.DeleteHost(v)
		}
	}

	return nil
}

func (h *Handler) GetDNSNotificationChannel() <-chan dns.DNSEntry {
	return h.dnsChannel
}

func (h *Handler) sendDNSNotification(dnsEntry dns.DNSEntry) {
	if len(h.dnsChannel) < cap(h.dnsChannel) { // protect from blocking
		h.dnsChannel <- dnsEntry
		return
	}
	fmt.Printf("packet: error dns channel is full len=%d %v\n", len(h.dnsChannel), dnsEntry)
}
