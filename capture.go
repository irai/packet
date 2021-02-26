package packet

import (
	"bytes"
	"net"
)

// StartHunt places the mac in capture mode
func (h *Handler) StartHunt(mac net.HardwareAddr) error {
	h.Lock()
	defer h.Unlock()

	if h.capturedIndex(mac) != -1 {
		return nil
	}

	if err := h.HandlerARP.StartHunt(mac); err != nil {
		return err
	}
	if err := h.HandlerICMP4.StartHunt(mac); err != nil {
		return err
	}
	if err := h.HandlerICMP6.StartHunt(mac); err != nil {
		return err
	}
	h.captureList = append(h.captureList, mac)
	return nil
}

// StopHunt removes the mac from capture mode
func (h *Handler) StopHunt(mac net.HardwareAddr) error {
	h.Lock()
	defer h.Unlock()

	var pos int
	if pos = h.capturedIndex(mac); pos == -1 {
		return nil
	}

	if err := h.HandlerICMP4.StopHunt(mac); err != nil {
		return err
	}
	if err := h.HandlerICMP6.StopHunt(mac); err != nil {
		return err
	}
	if err := h.HandlerARP.StopHunt(mac); err != nil {
		return err
	}

	if pos+1 == len(h.captureList) { // last element?
		h.captureList = h.captureList[:pos]
		return nil
	}
	copy(h.captureList[pos:], h.captureList[pos+1:])
	h.captureList = h.captureList[:len(h.captureList)-1]
	return nil
}

func (h *Handler) capturedIndex(mac net.HardwareAddr) int {
	for i := range h.captureList {
		if bytes.Equal(h.captureList[i], mac) {
			return i
		}
	}
	return -1
}
