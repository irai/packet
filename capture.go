package packet

import (
	"bytes"
	"fmt"
	"net"
)

// Capture places the mac in capture mode
func (h *Handler) Capture(mac net.HardwareAddr) error {
	h.Lock()
	macEntry := h.MACTable.findMAC(mac)
	if macEntry == nil {
		h.Unlock()
		return nil
	}
	macEntry.Captured = true

	list := []net.IP{}
	// Mark all known entries as StageHunt
	for _, v := range h.LANHosts.Table {
		if bytes.Equal(v.MACEntry.MAC, mac) {
			v.HuntStage = StageHunt
			list = append(list, v.IP)
		}
	}
	h.Unlock()

	for _, ip := range list {
		if err := h.lockAndStartHunt(ip); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) lockAndStartHunt(ip net.IP) error {
	// IP4 handlers
	if ip.To4() != nil {
		if err := h.HandlerARP.StartHunt(ip); err != nil {
			return err
		}
		if err := h.HandlerICMP4.StartHunt(ip); err != nil {
			return err
		}
		if err := h.HandlerDHCP4.StartHunt(ip); err != nil {
			return err
		}
		return nil
	}

	// IP6 handlers
	if err := h.HandlerICMP6.StartHunt(ip); err != nil {
		return err
	}
	return nil
}

// Release removes the mac from capture mode
func (h *Handler) Release(mac net.HardwareAddr) error {
	h.Lock()

	macEntry := h.MACTable.findMAC(mac)
	if macEntry == nil {
		h.Unlock()
		return nil
	}

	list := []net.IP{}
	// Mark all known entries as StageNormal
	for _, v := range h.LANHosts.Table {
		if bytes.Equal(v.MACEntry.MAC, mac) {
			v.HuntStage = StageNormal
			list = append(list, v.IP)
		}
	}

	macEntry.Captured = false
	h.Unlock()

	for _, ip := range list {
		if err := h.lockAndStopHunt(ip); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) lockAndStopHunt(ip net.IP) error {
	// IP4 handlers
	if ip.To4() != nil {
		if err := h.HandlerDHCP4.StopHunt(ip); err != nil {
			return err
		}
		if err := h.HandlerICMP4.StopHunt(ip); err != nil {
			return err
		}
		if err := h.HandlerARP.StopHunt(ip); err != nil {
			return err
		}
		return nil
	}

	// IP6 handlers
	if err := h.HandlerICMP6.StopHunt(ip); err != nil {
		return err
	}
	return nil
}

// IsCaptured return true is mac is in capture mode
func (h *Handler) IsCaptured(mac net.HardwareAddr) bool {
	h.Lock()
	defer h.Unlock()
	if e := h.FindMACEntryNoLock(mac); e != nil && e.Captured {
		return true
	}
	return false
}

func (h *Handler) checkIPChanged(host *Host) {
	fmt.Println("DEBUG: check ip changed ", host, host.MACEntry)
	// set macEntry current IP
	if host.IP.To4() != nil {
		if !host.MACEntry.IP4.Equal(host.IP) { // changed IP
			fmt.Printf("packet: host changed ip4 from=%s to=%s\n", host.MACEntry.IP4, host.IP)
			go h.lockAndSetOffline(host.MACEntry.IP4) // set previous host offline in goroutine as it will lock
			host.MACEntry.updateIP(host.IP)
		}
	} else {
		// Only interested in GUA changes
		if host.IP.IsGlobalUnicast() && !host.MACEntry.IP6GUA.Equal(host.IP) { // changed IP
			fmt.Printf("packet: host changed ip6 from=%s to=%s\n", host.MACEntry.IP6GUA, host.IP)
			go h.lockAndSetOffline(host.MACEntry.IP6GUA) // set previous host offline in goroutine as it will lock
			host.MACEntry.updateIP(host.IP)
		}
		if host.IP.To16().IsLinkLocalUnicast() && !host.MACEntry.IP6LLA.Equal(host.IP) { // changed IP
			fmt.Printf("packet: host changed ip6 from=%s to=%s\n", host.MACEntry.IP6LLA, host.IP)
			// go h.lockAndSetOffline(host.MACEntry.IP6LLA) // set previous host offline in goroutine as it will lock
			host.MACEntry.updateIP(host.IP)
		}
	}
}
