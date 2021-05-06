package packet

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/irai/packet/model"
)

// Capture places the mac in capture mode
func (h *Handler) Capture(mac net.HardwareAddr) error {
	h.mutex.Lock()
	macEntry := h.session.MACTable.FindOrCreateNoLock(mac)
	if macEntry.Captured {
		h.mutex.Unlock()
		return nil
	}
	if macEntry.IsRouter {
		h.mutex.Unlock()
		return model.ErrIsRouter
	}
	macEntry.Captured = true

	list := []model.Addr{}
	// Mark all known entries as model.StageHunt
	for _, host := range macEntry.HostList {
		list = append(list, model.Addr{IP: host.IP, MAC: host.MACEntry.MAC})
	}
	h.mutex.Unlock()

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
func (h *Handler) lockAndStartHunt(addr model.Addr) (err error) {

	host := h.session.FindIP(addr.IP)
	if host == nil {
		fmt.Printf("packet: error invalid ip in lockAndStartHunt ip=%s\n", addr.IP)
		return model.ErrInvalidIP
	}

	host.Row.Lock()
	if host.HuntStage == model.StageRedirected {
		fmt.Printf("packet: host successfully redirected %s\n", host)
		host.Row.Unlock()
		return nil
	}
	if !host.Online { // host offline, nothing to do
		host.Row.Unlock()
		return nil
	}
	if host.HuntStage == model.StageHunt {
		host.Row.Unlock()
		return nil
	}

	host.HuntStage = model.StageHunt
	/**
	host.icmp4Store.model.HuntStage = model.StageHunt
	host.dhcp4Store.model.HuntStage = model.StageHunt
	host.icmp6Store.model.HuntStage = model.StageHunt
	**/
	if Debug {
		fmt.Printf("packet: start hunt for %s\n", host)
	}
	host.Row.Unlock()

	// IP4 handlers
	if addr.IP.To4() != nil {
		go func() {
			if _, err = h.HandlerARP.StartHunt(addr); err != nil {
				fmt.Printf("packet: failed to start arp hunt: %s", err.Error())
			}
			if _, err = h.HandlerICMP4.StartHunt(addr); err != nil {
				fmt.Printf("packet: failed to start icmp4 hunt: %s", err.Error())
			}
			if _, err = h.HandlerDHCP4.StartHunt(addr); err != nil {
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
		if _, err = h.HandlerICMP6.StartHunt(addr); err != nil {
			fmt.Printf("packet: failed to start icmp6 hunt: %s", err.Error())
		}
	}()
	return nil
}

// Release removes the mac from capture mode
func (h *Handler) Release(mac net.HardwareAddr) error {
	h.mutex.Lock()

	macEntry := h.session.MACTable.FindMACNoLock(mac)
	if macEntry == nil {
		h.mutex.Unlock()
		return nil
	}
	list := []*model.Host{}
	list = append(list, macEntry.HostList...)
	macEntry.Captured = false

	h.mutex.Unlock()

	for _, host := range list {
		if err := h.lockAndStopHunt(host, model.StageNormal); err != nil {
			return err
		}
	}
	return nil
}

// lockAndStopHunt will stop hunting for all modules
//
// host could be in one of two states:
//  - model.StageHunt       - an active hunt is in progress
//  - model.StageRedirected - the host is redirected; typically called when host went offline
//                      or routing is no longer OK
//
func (h *Handler) lockAndStopHunt(host *model.Host, stage model.HuntStage) (err error) {
	host.Row.Lock()
	switch host.HuntStage {
	case model.StageNormal:
		host.Row.Unlock()
		return nil
	case model.StageRedirected:
		host.HuntStage = stage
		if Debug {
			fmt.Printf("packet: stop hunt for %s\n", host)
		}
		host.Row.Unlock()
		return nil
	}

	host.HuntStage = stage
	if Debug {
		fmt.Printf("packet: stop hunt for %s\n", host)
	}

	/**
	if host.icmp4Store.model.HuntStage == model.StageHunt {
		host.icmp4Store.model.HuntStage = model.StageNormal
	}
	if host.dhcp4Store.model.HuntStage == model.StageHunt {
		host.dhcp4Store.model.HuntStage = model.StageNormal
	}
	if host.icmp6Store.model.HuntStage == model.StageHunt {
		host.icmp6Store.model.HuntStage = model.StageNormal
	}
	**/
	addr := model.Addr{MAC: host.MACEntry.MAC, IP: host.IP}
	host.Row.Unlock()

	// IP4 handlers
	if addr.IP.To4() != nil {
		go func() {
			// DHCP4 will return not found if there is no lease entry; this is okay if the host has not acquired an IP yet
			if _, err = h.HandlerDHCP4.StopHunt(addr); err != nil && !errors.Is(err, model.ErrNotFound) {
				fmt.Printf("packet: failed to stop dhcp4 hunt: %s", err.Error())
			}
			if _, err = h.HandlerICMP4.StopHunt(addr); err != nil {
				fmt.Printf("packet: failed to stop icmp4 hunt: %s", err.Error())
			}
			if _, err = h.HandlerARP.StopHunt(addr); err != nil {
				fmt.Printf("packet: failed to stop arp hunt: %s", err.Error())
			}
		}()
		return nil
	}

	// IP6 handlers
	go func() {
		if _, err = h.HandlerICMP6.StopHunt(addr); err != nil {
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
		if host.HuntStage == model.StageRedirected && host.IP.To4() != nil {
			addr := model.Addr{MAC: host.MACEntry.MAC, IP: host.IP}
			host.Row.RUnlock()
			_, err := h.HandlerICMP4.CheckAddr(addr) // ping host
			if errors.Is(err, model.ErrNotRedirected) {
				fmt.Printf("packet: ip4 routing NOK %s\n", host)
				// Call stop hunt first to update stage to normal
				if err := h.lockAndStopHunt(host, model.StageNormal); err != nil {
					fmt.Printf("packet: failed to stop hunt %s error=\"%s\"\n", host, err)
				}
				if err := h.lockAndStartHunt(addr); err != nil {
					fmt.Printf("packet: failed to start hunt %s error=\"%s\"\n", host, err)
				}
			} else {
				if err == nil && Debug {
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
