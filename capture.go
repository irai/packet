package packet

import (
	"fmt"
	"net"
	"time"
)

// Capture places the mac in capture mode
func (h *Handler) Capture(mac net.HardwareAddr) error {
	h.mutex.Lock()
	macEntry := h.MACTable.findOrCreate(mac)
	if macEntry.Captured {
		h.mutex.Unlock()
		return nil
	}
	macEntry.Captured = true

	list := []Addr{}
	// Mark all known entries as StageHunt
	for _, host := range macEntry.HostList {
		list = append(list, Addr{IP: host.IP, MAC: host.MACEntry.MAC})
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

func (h *Handler) lockAndStartHunt(addr Addr) (err error) {
	if Debug {
		fmt.Printf("packet: lockAndStartHunt for %s\n", addr)
	}

	host := h.FindIP(addr.IP)
	if host == nil {
		fmt.Printf("packet: error invalid ip in lockAndStartHunt ip=%s\n", addr.IP)
		return ErrInvalidIP
	}

	host.Row.Lock()
	if host.huntStage == StageRedirected {
		fmt.Printf("packet: host successfully redirected %s\n", host)
		host.Row.Unlock()
		return nil
	}
	if !host.Online { // host offline, nothing to do
		host.Row.Unlock()
		return nil
	}
	if host.huntStage == StageHunt {
		host.Row.Unlock()
		return nil
	}

	host.huntStage = StageHunt
	host.arpStore.HuntStage = StageHunt
	host.icmp4Store.HuntStage = StageHunt
	host.dhcp4Store.HuntStage = StageHunt
	host.icmp6Store.HuntStage = StageHunt
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
		if _, err = h.HandlerICMP6.StartHunt(addr); err != nil {
			fmt.Printf("packet: failed to start icmp6 hunt: %s", err.Error())
		}
	}()
	return nil
}

// Release removes the mac from capture mode
func (h *Handler) Release(mac net.HardwareAddr) error {
	h.mutex.Lock()

	macEntry := h.MACTable.findMAC(mac)
	if macEntry == nil {
		h.mutex.Unlock()
		return nil
	}
	list := []*Host{}
	list = append(list, macEntry.HostList...)
	macEntry.Captured = false

	h.mutex.Unlock()

	for _, host := range list {
		if err := h.lockAndStopHunt(host); err != nil {
			return err
		}
	}
	return nil
}

// lockAndStopHunt will stop hunting for all modules
// host could be in one of two states:
//  - StageHunt       - an active hunt is in progress
//  - StageRedirected - the host is redirected
//
func (h *Handler) lockAndStopHunt(host *Host) (err error) {
	host.Row.Lock()
	if host.huntStage == StageNormal {
		host.Row.Unlock()
		return nil
	}
	if Debug {
		fmt.Printf("packet: end hunt for %s\n", host)
	}

	// Keep host in StageRedirected is stop hunting because of redirection
	if host.huntStage == StageHunt || !host.Online {
		host.huntStage = StageNormal
	}
	if host.arpStore.HuntStage == StageHunt {
		host.arpStore.HuntStage = StageNormal
	}
	if host.icmp4Store.HuntStage == StageHunt {
		host.icmp4Store.HuntStage = StageNormal
	}
	if host.dhcp4Store.HuntStage == StageHunt {
		host.dhcp4Store.HuntStage = StageNormal
	}
	if host.icmp6Store.HuntStage == StageHunt {
		host.icmp6Store.HuntStage = StageNormal
	}
	addr := Addr{MAC: host.MACEntry.MAC, IP: host.IP}
	host.Row.Unlock()

	// IP4 handlers
	if addr.IP.To4() != nil {
		go func() {
			if _, err = h.HandlerDHCP4.StopHunt(addr); err != nil {
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

// IsCaptured return true is mac is in capture mode
func (h *Handler) IsCaptured(mac net.HardwareAddr) bool {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	if e := h.MACTable.findMAC(mac); e != nil && e.Captured {
		return true
	}
	return false
}

// routeMonitor monitors the default gateway is still pointing to us
func (h *Handler) routeMonitor(now time.Time) (err error) {
	h.mutex.RLock()
	for _, host := range h.LANHosts.Table {
		host.Row.RLock()
		if host.huntStage == StageRedirected && host.IP.To4() != nil {
			addr := Addr{MAC: host.MACEntry.MAC, IP: host.IP}
			host.Row.RUnlock()
			stage := h.HandlerICMP4.HuntStage(addr)
			if stage == StageHunt {
				h.lockAndTransitionHuntStage(host, StageNoChange, stage)
			}
			host.Row.RLock()
		}
		host.Row.RUnlock()
	}
	h.mutex.RUnlock()

	return nil
}

func (h *Handler) lockAndTransitionHuntStage(host *Host, dhcp4Stage HuntStage, icmp4Stage HuntStage) {
	if Debug {
		fmt.Printf("packet: transitioning hunt state dhcp4Stage=%v icmp4Stage=%v\n", dhcp4Stage, icmp4Stage)
	}
	if dhcp4Stage == StageNoChange {
		dhcp4Stage = host.dhcp4Store.HuntStage
	}
	// if icmp4Stage == StageNoChange {
	// icmp4Stage = host.icmp4Store.HuntStage
	// }

	newStage := dhcp4Stage
	if dhcp4Stage == StageRedirected {
		newStage = StageRedirected
		if icmp4Stage == StageHunt { // override dhcp4
			fmt.Printf("packet: ip4 routing NOK %s\n", host)
			newStage = StageHunt
		}
	}

	if host.huntStage == newStage {
		return
	}

	host.huntStage = newStage
	if host.huntStage == StageHunt {
		go h.lockAndStartHunt(Addr{MAC: host.MACEntry.MAC, IP: host.IP})
		return
	}

	h.lockAndStopHunt(host)
}
