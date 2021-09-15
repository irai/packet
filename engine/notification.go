package engine

import (
	"fmt"
	"net"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/dns"
	"github.com/irai/packet/fastlog"
)

type Notification struct {
	Addr      packet.Addr
	Online    bool
	DHCP4Name packet.NameEntry
	MDNSName  packet.NameEntry
	SSDPName  packet.NameEntry
	LLMNRName packet.NameEntry
	NBNSName  packet.NameEntry
	IsRouter  bool
}

func (n Notification) String() string {
	line := fastlog.NewLine("", "")
	n.FastLog(line)
	return line.ToString()
}

func (n Notification) FastLog(l *fastlog.Line) *fastlog.Line {
	l.Struct(n.Addr)
	l.Bool("online", n.Online)
	l.Struct(n.DHCP4Name)
	l.Struct(n.MDNSName)
	l.Struct(n.SSDPName)
	l.Struct(n.LLMNRName)
	l.Struct(n.NBNSName)
	l.Bool("router", n.IsRouter)
	return l
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

func toNotification(host *packet.Host) Notification {
	// send the MACEntry name as there can be many IPv6 hosts, some with name entries not populated yet
	return Notification{Addr: host.Addr, Online: host.Online,
		DHCP4Name: host.MACEntry.DHCP4Name, MDNSName: host.MACEntry.MDNSName, SSDPName: host.MACEntry.SSDPName,
		LLMNRName: host.LLMNRName, NBNSName: host.MACEntry.NBNSName,
		IsRouter: host.MACEntry.IsRouter}
}

func (h *Handler) sendNotification(notification Notification) {
	if len(h.notificationChannel) < cap(h.notificationChannel) {
		h.notificationChannel <- notification
		return
	}
	fmt.Printf("packet: error notification channel is full len=%d %v\n", len(h.notificationChannel), notification)
}

func (h *Handler) GetNotificationChannel() <-chan Notification {
	return h.notificationChannel
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
