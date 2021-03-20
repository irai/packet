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

func (h *Handler) lockAndStartHunt(addr Addr) error {
	if Debug {
		fmt.Printf("packet: start hunt for %s\n", addr)
	}
	dhcp4Stage := StageNormal
	if addr.IP.To4() != nil {
		dhcp4Stage = h.HandlerDHCP4.HuntStage(addr)
	}

	h.mutex.Lock()
	host := h.FindIPNoLock(addr.IP)
	if host == nil {
		h.mutex.Unlock()
		fmt.Printf("packet: error invalid ip in lockAndStartHunt ip=%s\n", addr.IP)
		return ErrInvalidIP
	}

	if dhcp4Stage == StageRedirected {
		host.huntStage = StageRedirected
		h.mutex.Unlock()
		fmt.Printf("packet: host successfully redirected %s\n", addr)
		return nil
	}

	host.huntStage = StageHunt
	h.mutex.Unlock()

	// IP4 handlers
	if addr.IP.To4() != nil {
		if err := h.HandlerARP.StartHunt(addr.IP); err != nil {
			return err
		}
		if err := h.HandlerICMP4.StartHunt(addr.IP); err != nil {
			return err
		}
		if err := h.HandlerDHCP4.StartHunt(addr.IP); err != nil {
			return err
		}
		return nil
	}

	// IP6 handlers
	if err := h.HandlerICMP6.StartHunt(addr.IP); err != nil {
		return err
	}
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

	list := []net.IP{}
	// Mark all known entries as StageNormal
	for _, v := range macEntry.HostList {
		list = append(list, v.IP)
	}

	macEntry.Captured = false
	h.mutex.Unlock()

	for _, ip := range list {
		if err := h.lockAndStopHunt(ip); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) lockAndStopHunt(ip net.IP) error {
	h.mutex.Lock()
	host := h.FindIPNoLock(ip)
	if host == nil {
		h.mutex.Unlock()
		fmt.Printf("packet: error invalid ip in lockAndStopHunt ip=%s\n", ip)
		return ErrInvalidIP
	}
	if host.huntStage != StageHunt {
		h.mutex.Unlock()
		fmt.Printf("packet: host not in hunt stage ip=%s\n", ip)
		return ErrInvalidIP
	}
	host.huntStage = StageNormal
	h.mutex.Unlock()

	if Debug {
		fmt.Printf("packet: end hunt for ip=%s\n", ip)
	}

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
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if e := h.FindMACEntryNoLock(mac); e != nil && e.Captured {
		return true
	}
	return false
}

// routeMonitor monitors the default gateway is still pointing to us
func (h *Handler) routeMonitor(now time.Time) (err error) {
	ip4Addrs := []Addr{}
	h.mutex.Lock()
	for _, host := range h.LANHosts.Table {
		if host.huntStage == StageRedirected && host.IP.To4() != nil {
			ip4Addrs = append(ip4Addrs, Addr{IP: host.IP, MAC: host.MACEntry.MAC})
		}
	}
	h.mutex.Unlock()

	for _, addr := range ip4Addrs {
		stage := h.HandlerICMP4.HuntStage(addr)
		switch stage {
		case StageHunt:
			fmt.Printf("packet: ip4 routing NOK ip=%s mac=%s\n", addr.IP, addr.MAC)
			h.lockAndStartHunt(addr)
		case StageRedirected:
			if Debug {
				fmt.Printf("packet: ip4 routing OK ip=%s mac=%s\n", addr.IP, addr.MAC)
			}
		}
	}
	return nil
}
