package packet

import (
	"fmt"
	"net"
	"time"
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
	for _, v := range macEntry.HostList {
		list = append(list, v.IP)
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
	h.Lock()
	host := h.FindIPNoLock(ip)
	if host == nil {
		h.Unlock()
		fmt.Printf("packet: error invalid ip in lockAndStartHunt ip=%s\n", ip)
		return ErrInvalidIP
	}
	host.huntStage = StageHunt
	h.Unlock()

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
	for _, v := range macEntry.HostList {
		list = append(list, v.IP)
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
	h.Lock()
	host := h.FindIPNoLock(ip)
	if host == nil {
		h.Unlock()
		fmt.Printf("packet: error invalid ip in lockAndStopHunt ip=%s\n", ip)
		return ErrInvalidIP
	}
	host.huntStage = StageNormal
	h.Unlock()

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

func (h *Handler) routeMonitorLoop(interval time.Duration) (err error) {
	if interval < time.Second*10 {
		interval = time.Second * 10
	}

	for {
		ip4Addrs := []Addr{}
		h.Lock()
		for _, host := range h.LANHosts.Table {
			if host.huntStage == StageRedirected && host.IP.To4() != nil {
				ip4Addrs = append(ip4Addrs, Addr{IP: host.IP, MAC: host.MACEntry.MAC})
			}
		}
		h.Unlock()

		if h.IP4RouteValidation != nil {
			for _, addr := range ip4Addrs {
				stage := h.IP4RouteValidation(addr)
				switch stage {
				case StageHunt:
					fmt.Printf("packet: ip4 routing NOK ip=%s mac=%s\n", addr.IP, addr.MAC)
					h.lockAndStartHunt(addr.IP)
				case StageRedirected:
					if Debug {
						fmt.Printf("packet: ip4 routing OK ip=%s mac=%s\n", addr.IP, addr.MAC)
					}
				}
			}
		}
		select {
		case <-h.closeChan:
			return
		case <-time.After(interval):
		}
	}
}
