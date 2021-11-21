package packet

import (
	"fmt"

	"github.com/irai/packet/fastlog"
)

type Notification struct {
	Addr         Addr
	Online       bool
	Manufacturer string
	DHCP4Name    NameEntry
	MDNSName     NameEntry
	SSDPName     NameEntry
	LLMNRName    NameEntry
	NBNSName     NameEntry
	IsRouter     bool
}

func (n Notification) String() string {
	line := fastlog.NewLine("", "")
	n.FastLog(line)
	return line.ToString()
}

func (n Notification) FastLog(l *fastlog.Line) *fastlog.Line {
	l.Struct(n.Addr)
	l.Bool("online", n.Online)
	if n.Manufacturer != "" {
		l.String("manufacturer", n.Manufacturer)
	}
	l.Struct(n.DHCP4Name)
	l.Struct(n.MDNSName)
	l.Struct(n.SSDPName)
	l.Struct(n.LLMNRName)
	l.Struct(n.NBNSName)
	l.Bool("router", n.IsRouter)
	return l
}

func toNotification(host *Host) Notification {
	// send the MACEntry name as there can be many IPv6 hosts, some with name entries not populated yet
	return Notification{Addr: host.Addr, Online: host.Online, Manufacturer: host.MACEntry.Manufacturer,
		DHCP4Name: host.MACEntry.DHCP4Name, MDNSName: host.MACEntry.MDNSName, SSDPName: host.MACEntry.SSDPName,
		LLMNRName: host.LLMNRName, NBNSName: host.MACEntry.NBNSName,
		IsRouter: host.MACEntry.IsRouter}
}

func (h *Session) sendNotification(notification Notification) {
	if len(h.C) < cap(h.C) {
		h.C <- notification
		return
	}
	fmt.Printf("packet: error notification channel is full len=%d %v\n", len(h.C), notification)
}

func (h *Session) GetNotificationChannel() <-chan Notification {
	return h.C
}
