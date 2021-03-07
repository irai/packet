package packet

import (
	"bytes"
	"net"
)

// Capture places the mac in capture mode
func (h *Handler) Capture(mac net.HardwareAddr) error {
	h.Lock()
	if h.captureList.Index(mac) != -1 {
		h.Unlock()
		return nil
	}
	h.captureList.Add(mac)

	list := []net.IP{}
	// Mark all known entries as StageHunt
	for _, v := range h.LANHosts.Table {
		if bytes.Equal(v.MAC, mac) {
			v.HuntStageIP4 = StageHunt
			v.HuntStageIP6 = StageHunt
			list = append(list, v.IP)
		}
	}
	h.Unlock()

	for _, v := range list {
		if v.To4() != nil {
			if err := h.startIP4HuntHandlers(v); err != nil {
				return err
			}
		} else {
			if err := h.startIP6HuntHandlers(v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *Handler) startIP4HuntHandlers(ip net.IP) error {
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
func (h *Handler) startIP6HuntHandlers(ip net.IP) error {
	if err := h.HandlerICMP6.StartHunt(ip); err != nil {
		return err
	}
	return nil
}

// Release removes the mac from capture mode
func (h *Handler) Release(mac net.HardwareAddr) error {
	h.Lock()

	if pos := h.captureList.Index(mac); pos == -1 {
		h.Unlock()
		return nil
	}

	list := []net.IP{}
	// Mark all known entries as StageNormal
	for _, v := range h.LANHosts.Table {
		if bytes.Equal(v.MAC, mac) {
			v.HuntStageIP4 = StageNormal
			v.HuntStageIP6 = StageNormal
			list = append(list, v.IP)
		}
	}
	h.Unlock()

	for _, ip := range list {
		if ip.To4() != nil {
			if err := h.stopIP4HuntHandlers(ip); err != nil {
				return err
			}
		} else {
			if err := h.stopIP6HuntHandlers(ip); err != nil {
				return err
			}
		}
	}
	h.captureList.Del(mac)
	return nil
}

func (h *Handler) stopIP4HuntHandlers(ip net.IP) error {
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

func (h *Handler) stopIP6HuntHandlers(ip net.IP) error {
	if err := h.HandlerICMP6.StopHunt(ip); err != nil {
		return err
	}
	return nil
}
