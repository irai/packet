package packet

import (
	"bytes"
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
			v.HuntStageIP4 = StageHunt
			v.HuntStageIP6 = StageHunt
			list = append(list, v.IP)
		}
	}
	h.Unlock()

	for _, ip := range list {
		if err := h.startHunt(ip); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) startHunt(ip net.IP) error {
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
			v.HuntStageIP4 = StageNormal
			v.HuntStageIP6 = StageNormal
			list = append(list, v.IP)
		}
	}

	macEntry.Captured = false
	h.Unlock()

	for _, ip := range list {
		if err := h.stopHunt(ip); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) stopHunt(ip net.IP) error {
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
	if e := h.FindMACEntry(mac); e != nil && e.Captured {
		return true
	}
	return false
}
