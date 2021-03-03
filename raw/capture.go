package raw

import (
	"net"
)

// StartHunt places the mac in capture mode
func (h *Handler) StartHunt(mac net.HardwareAddr) error {
	h.Lock()
	defer h.Unlock()

	if h.captureList.Index(mac) != -1 {
		return nil
	}
	if err := h.startHuntHandlers(mac); err != nil {
		return err
	}
	h.captureList.Add(mac)
	return nil
}

func (h *Handler) startHuntHandlers(mac net.HardwareAddr) error {
	if err := h.HandlerARP.StartHunt(mac); err != nil {
		return err
	}
	if err := h.HandlerICMP4.StartHunt(mac); err != nil {
		return err
	}
	if err := h.HandlerICMP6.StartHunt(mac); err != nil {
		return err
	}
	return nil
}

// StopHunt removes the mac from capture mode
func (h *Handler) StopHunt(mac net.HardwareAddr) error {
	h.Lock()
	defer h.Unlock()

	var pos int
	if pos = h.captureList.Index(mac); pos == -1 {
		return nil
	}
	if err := h.stopHuntHandlers(mac); err != nil {
		return err
	}
	h.captureList.Del(mac)
	return nil
}

func (h *Handler) stopHuntHandlers(mac net.HardwareAddr) error {
	if err := h.HandlerICMP4.StopHunt(mac); err != nil {
		return err
	}
	if err := h.HandlerICMP6.StopHunt(mac); err != nil {
		return err
	}
	if err := h.HandlerARP.StopHunt(mac); err != nil {
		return err
	}

	return nil
}
