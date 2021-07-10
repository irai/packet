package engine

import (
	"fmt"
	"net"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/dns"
)

type Notification struct {
	Addr         packet.Addr
	Online       bool
	DHCPName     string
	MDNSName     string
	UPNPName     string
	Model        string
	Manufacturer string
	IsRouter     bool
}

func (n Notification) String() string {
	return fmt.Sprintf("%s online=%t dhcp4name=%s mdnsname=%s upnpname=%s model=%s manufacturer=%s router=%v",
		n.Addr, n.Online, n.DHCPName, n.MDNSName, n.UPNPName, n.Model, n.Manufacturer, n.IsRouter)
}

// purge is called each minute by the minute goroutine
func (h *Handler) purge(now time.Time, probeDur time.Duration, offlineDur time.Duration, purgeDur time.Duration) error {

	probeCutoff := now.Add(probeDur * -1)     // Mark offline entries last updated before this time
	offlineCutoff := now.Add(offlineDur * -1) // Mark offline entries last updated before this time
	deleteCutoff := now.Add(purgeDur * -1)    // Delete entries that have not responded in last hour

	purge := make([]net.IP, 0, 16)
	offline := make([]*packet.Host, 0, 16)

	h.session.GlobalRLock()
	for _, e := range h.session.HostTable.Table {
		e.MACEntry.Row.RLock()

		// Delete from table if the device is offline and was not seen for the last hour
		if !e.Online && e.LastSeen.Before(deleteCutoff) {
			purge = append(purge, e.Addr.IP)
			e.MACEntry.Row.RUnlock()
			continue
		}

		// Probe if device not seen recently
		if e.Online && e.LastSeen.Before(probeCutoff) {
			if ip := e.Addr.IP.To4(); ip != nil {
				h.ARPHandler.CheckAddr(packet.Addr{MAC: e.MACEntry.MAC, IP: ip})
			} else {
				h.ICMP6Handler.CheckAddr(packet.Addr{MAC: e.MACEntry.MAC, IP: e.Addr.IP})
			}
		}

		// Set offline if no updates since the offline deadline
		if e.Online && e.LastSeen.Before(offlineCutoff) {
			offline = append(offline, e)
		}
		e.MACEntry.Row.RUnlock()
	}
	h.session.GlobalRUnlock()

	for _, host := range offline {
		h.lockAndSetOffline(host) // will lock/unlock row
	}

	// delete after loop because this will change the table
	if len(purge) > 0 {
		for _, v := range purge {
			h.session.DeleteHost(v)
		}
	}

	return nil
}

func (h *Handler) GetNotificationChannel() <-chan Notification {
	if h.notificationChannel != nil {
		return h.notificationChannel
	}

	// Notify of all existing hosts
	list := []Notification{}
	h.session.GlobalRLock()
	for _, host := range h.session.HostTable.Table {
		host.MACEntry.Row.RLock()
		notification := Notification{Addr: host.Addr, Online: host.Online,
			DHCPName: host.DHCP4Name, MDNSName: host.MDNSName, UPNPName: host.UPNPName,
			Model: host.Model, Manufacturer: host.Manufacturer,
			IsRouter: host.MACEntry.IsRouter}
		list = append(list, notification)
		host.MACEntry.Row.RUnlock()
	}
	h.session.GlobalRUnlock()

	h.notificationChannel = make(chan Notification, notificationChannelCap)

	go func() {
		for _, n := range list {
			h.notificationChannel <- n
			time.Sleep(time.Millisecond * 5) // time for reader to process
		}
	}()

	return h.notificationChannel
}

func (h *Handler) GetDNSNotificationChannel() <-chan dns.DNSEntry {
	if h.dnsChannel != nil {
		return h.dnsChannel
	}

	h.dnsChannel = make(chan dns.DNSEntry, 16)
	return h.dnsChannel
}
