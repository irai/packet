package engine

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/irai/packet"
)

// Capture places the mac in capture mode
func (h *Handler) Capture(mac net.HardwareAddr) error {
	h.session.GlobalLock()
	macEntry := h.session.MACTable.FindOrCreateNoLock(mac)
	if macEntry.Captured {
		h.session.GlobalUnlock()
		return nil
	}
	if macEntry.IsRouter {
		h.session.GlobalUnlock()
		return packet.ErrIsRouter
	}
	macEntry.Captured = true

	// Mark all known entries as packet.StageHunt
	list := []packet.Addr{}
	for _, host := range macEntry.HostList {
		list = append(list, packet.Addr{IP: host.IP, MAC: host.MACEntry.MAC})
	}
	h.session.GlobalUnlock()

	go func() {
		for _, addr := range list {
			if err := h.lockAndStartHunt(addr); err != nil {
				fmt.Printf("packet: error in initial capture ip=%s error=%s\n", addr.IP, err)
			}
		}
	}()
	return nil
}

// lockAndStartHunt controls when to start the hunt process
//
// the following situations are possible:
//   - capture command issued by user
//   - host has come online
//   - icmp ping no longer redirected
func (h *Handler) lockAndStartHunt(addr packet.Addr) (err error) {

	host := h.session.FindIP(addr.IP)
	if host == nil {
		fmt.Printf("packet: error invalid ip in lockAndStartHunt ip=%s\n", addr.IP)
		return packet.ErrInvalidIP
	}

	host.Row.Lock()
	if host.HuntStage == packet.StageRedirected {
		fmt.Printf("packet: host successfully redirected %s\n", host)
		host.Row.Unlock()
		return nil
	}
	if !host.Online { // host offline, nothing to do
		host.Row.Unlock()
		return nil
	}
	if host.HuntStage == packet.StageHunt {
		host.Row.Unlock()
		return nil
	}

	host.HuntStage = packet.StageHunt
	/**
	host.icmp4Store.packet.HuntStage = packet.StageHunt
	host.dhcp4Store.packet.HuntStage = packet.StageHunt
	host.icmp6Store.packet.HuntStage = packet.StageHunt
	**/
	if packet.Debug {
		fmt.Printf("packet: start hunt for %s\n", host)
	}
	host.Row.Unlock()

	// IP4 handlers
	if addr.IP.To4() != nil {
		go func() {
			if _, err = h.ARPHandler.StartHunt(addr); err != nil {
				fmt.Printf("packet: failed to start arp hunt: %s", err.Error())
			}
			if _, err = h.ICMP4Handler.StartHunt(addr); err != nil {
				fmt.Printf("packet: failed to start icmp4 hunt: %s", err.Error())
			}
			if _, err = h.DHCP4Handler.StartHunt(addr); err != nil {
				fmt.Printf("packet: failed to start dhcp4 hunt: %s", err.Error())
			}
		}()
		return nil
	}

	// IP6 handlers
	go func() {
		// IP6 hunts local link layer IP, not Global Unique Address IP
		if host.MACEntry.IP6LLA == nil {
			fmt.Printf("packet: invalid LLA - failed to hunt %s host %s\n", addr, host)
			return
		}
		addr.IP = host.MACEntry.IP6LLA
		if _, err = h.ICMP6Handler.StartHunt(addr); err != nil {
			fmt.Printf("packet: failed to start icmp6 hunt: %s", err.Error())
		}
	}()
	return nil
}

// Release removes the mac from capture mode
func (h *Handler) Release(mac net.HardwareAddr) error {
	h.session.GlobalLock()
	macEntry := h.session.MACTable.FindMACNoLock(mac)
	if macEntry == nil {
		h.session.GlobalUnlock()
		return nil
	}
	list := []*packet.Host{}
	list = append(list, macEntry.HostList...)
	macEntry.Captured = false
	h.session.GlobalUnlock()

	for _, host := range list {
		if err := h.lockAndStopHunt(host, packet.StageNormal); err != nil {
			return err
		}
	}
	return nil
}

// lockAndStopHunt will stop hunting for all modules
//
// host could be in one of two states:
//  - packet.StageHunt       - an active hunt is in progress
//  - packet.StageRedirected - the host is redirected; typically called when host went offline
//                      or routing is no longer OK
//
func (h *Handler) lockAndStopHunt(host *packet.Host, stage packet.HuntStage) (err error) {
	host.Row.Lock()
	switch host.HuntStage {
	case packet.StageNormal:
		host.Row.Unlock()
		return nil
	case packet.StageRedirected:
		host.HuntStage = stage
		if packet.Debug {
			fmt.Printf("packet: stop hunt for %s\n", host)
		}
		host.Row.Unlock()
		return nil
	}

	host.HuntStage = stage
	if packet.Debug {
		fmt.Printf("packet: stop hunt for %s\n", host)
	}

	/**
	if host.icmp4Store.packet.HuntStage == packet.StageHunt {
		host.icmp4Store.packet.HuntStage = packet.StageNormal
	}
	if host.dhcp4Store.packet.HuntStage == packet.StageHunt {
		host.dhcp4Store.packet.HuntStage = packet.StageNormal
	}
	if host.icmp6Store.packet.HuntStage == packet.StageHunt {
		host.icmp6Store.packet.HuntStage = packet.StageNormal
	}
	**/
	addr := packet.Addr{MAC: host.MACEntry.MAC, IP: host.IP}
	host.Row.Unlock()

	// IP4 handlers
	if addr.IP.To4() != nil {
		go func() {
			// DHCP4 will return not found if there is no lease entry; this is okay if the host has not acquired an IP yet
			if _, err = h.DHCP4Handler.StopHunt(addr); err != nil && !errors.Is(err, packet.ErrNotFound) {
				fmt.Printf("packet: failed to stop dhcp4 hunt: %s", err.Error())
			}
			if _, err = h.ICMP4Handler.StopHunt(addr); err != nil {
				fmt.Printf("packet: failed to stop icmp4 hunt: %s", err.Error())
			}
			if _, err = h.ARPHandler.StopHunt(addr); err != nil {
				fmt.Printf("packet: failed to stop arp hunt: %s", err.Error())
			}
		}()
		return nil
	}

	// IP6 handlers
	go func() {
		if _, err = h.ICMP6Handler.StopHunt(addr); err != nil {
			fmt.Printf("packet: failed to stop icmp6 hunt: %s", err.Error())
		}
	}()
	return nil
}

// lockAndMonitorRoute monitors the default gateway is still pointing to us
func (h *Handler) lockAndMonitorRoute(now time.Time) (err error) {
	table := h.session.GetHosts()
	for _, host := range table {
		host.Row.RLock()
		if host.HuntStage == packet.StageRedirected && host.IP.To4() != nil {
			addr := packet.Addr{MAC: host.MACEntry.MAC, IP: host.IP}
			host.Row.RUnlock()
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
			host.Row.RLock()
		}
		host.Row.RUnlock()
	}

	return nil
}
