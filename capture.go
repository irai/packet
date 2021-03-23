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
	if Debug {
		fmt.Printf("packet: start hunt for %s\n", host)
	}
	host.Row.Unlock()

	// IP4 handlers
	arpStage := StageNoChange
	icmp4Stage := StageNoChange
	dhcp4Stage := StageNoChange
	if addr.IP.To4() != nil {
		if arpStage, err = h.HandlerARP.StartHunt(addr); err != nil {
			return err
		}
		if icmp4Stage, err = h.HandlerICMP4.StartHunt(addr); err != nil {
			return err
		}
		if dhcp4Stage, err = h.HandlerDHCP4.StartHunt(addr); err != nil {
			return err
		}
		host.Row.Lock()
		host.arpStore.HuntStage = arpStage
		host.icmp4Store.HuntStage = icmp4Stage
		host.dhcp4Store.HuntStage = dhcp4Stage
		host.Row.Unlock()
		return nil
	}

	// IP6 handlers
	icmp6Stage := StageNoChange
	if icmp6Stage, err = h.HandlerICMP6.StartHunt(addr); err != nil {
		return err
	}
	host.Row.Lock()
	host.icmp6Store.HuntStage = icmp6Stage
	host.Row.Unlock()
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
		if err := h.stopHunt(host); err != nil {
			return err
		}
	}
	return nil
}

// stopHunt will stop hunting for all modules
//
// Host must be locked for writing
func (h *Handler) stopHunt(host *Host) (err error) {
	if host.huntStage != StageHunt {
		fmt.Printf("packet: stopHunt host not in hunt stage %s\n", host)
		return ErrInvalidIP
	}

	host.huntStage = StageNormal
	if Debug {
		fmt.Printf("packet: end hunt for %s\n", host)
	}
	addr := Addr{MAC: host.MACEntry.MAC, IP: host.IP}

	// IP4 handlers
	if host.IP.To4() != nil {
		arpStage := StageNoChange
		icmp4Stage := StageNoChange
		dhcp4Stage := StageNoChange

		if dhcp4Stage, err = h.HandlerDHCP4.StopHunt(addr); err != nil {
			return err
		}
		if icmp4Stage, err = h.HandlerICMP4.StopHunt(addr); err != nil {
			return err
		}
		if arpStage, err = h.HandlerARP.StopHunt(addr); err != nil {
			return err
		}
		host.Row.Lock()
		host.arpStore.HuntStage = arpStage
		host.icmp4Store.HuntStage = icmp4Stage
		host.dhcp4Store.HuntStage = dhcp4Stage
		host.Row.Unlock()
		return nil
	}

	// IP6 handlers
	icmp6Stage := StageNoChange
	if icmp6Stage, err = h.HandlerICMP6.StopHunt(addr); err != nil {
		return err
	}
	host.Row.Lock()
	host.icmp6Store.HuntStage = icmp6Stage
	host.Row.Unlock()
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
	hosts := []*Host{}
	h.mutex.RLock()
	for _, host := range h.LANHosts.Table {
		host.Row.RLock()
		if host.huntStage == StageRedirected && host.IP.To4() != nil {
			hosts = append(hosts, host)
		}
		host.Row.RUnlock()
	}
	h.mutex.RUnlock()

	for _, host := range hosts {
		h.transitionHuntStage(host, StageNoChange, StageHunt)
	}
	return nil
}

func (h *Handler) transitionHuntStage(host *Host, dhcp4Stage HuntStage, icmp4Stage HuntStage) {
	if dhcp4Stage == StageNoChange {
		dhcp4Stage = host.dhcp4Store.HuntStage
	}
	if icmp4Stage == StageNoChange {
		icmp4Stage = host.icmp4Store.HuntStage
	}

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

	h.stopHunt(host)
}
