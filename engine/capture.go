package engine

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/irai/packet"
)

// Stage transitions identify how the engine behave in various states
//
// MACEntry State records if the mac address is being captured or not. Possible values:
//  - Capture - the mac was set to capture by the user
//  - Normal  - initial value or it was subsequently set by user
//
// Host transitions include:
//  - online  - the IP address is actively trasnmismitting on the network
//              transition to online generates a host notification event
//  - offline - the IP address has stopped transmitting and will be purged in the near future if not
//              the deadline for an IP to move to offline is set via the OfflineDeadline field in the handler
//              transition to offline generates a host notification event
//              the IP will be purged
//
// A host may also be in one of the following hunt stages:
//  - normal      the host is not captured and there is nothing to do
//  - hunt        the host is activelly being hunted by each plugin.
//                the arp plugin will spoof the mac address
//                the icmp6 plugin will spoof the neighbor discovery protocol
//  - redirected  the host is redirected via dhcp and is activelly sending traffic to netfilter

// Capture set the mac to capture mode
func (h *Handler) Capture(mac net.HardwareAddr) error {
	h.session.GlobalLock()
	macEntry := h.session.MACTable.FindOrCreateNoLock(mac)
	if macEntry.Captured {
		h.session.GlobalUnlock()
		return nil
	}
	if macEntry.IsRouter {
		h.session.GlobalUnlock()
		return packet.ErrIsRouter
	}
	macEntry.Captured = true

	list := []packet.Addr{}
	for _, host := range macEntry.HostList {
		list = append(list, packet.Addr{IP: host.Addr.IP, MAC: host.MACEntry.MAC})
	}
	h.session.GlobalUnlock()

	for _, addr := range list {
		if err := h.lockAndStartHunt(addr); err != nil {
			fmt.Printf("packet: error in initial capture ip=%s error=%s\n", addr.IP, err)
		}
	}

	// There is a chance that we don't have the IPv6 LLA for host as mobile
	// hosts don't always respond to ping ff02::1.
	//
	// Then, force hunt using a multicast IPv6 as the target host
	// This call will be ignored if the host was already captured above
	ipv6Addr := packet.Addr{MAC: mac, IP: nil}
	if _, err := h.ICMP6Handler.StartHunt(ipv6Addr); err != nil {
		fmt.Printf("packet: failed to start icmp6 hunt: %s", err.Error())
	}

	// ping IPv6 all nodes to capture any lagging host
	h.ICMP6Handler.CheckAddr(packet.Addr{MAC: mac, IP: packet.IP6AllNodesMulticast})

	return nil
}

// Release removes the mac from capture mode
func (h *Handler) Release(mac net.HardwareAddr) error {
	h.session.GlobalLock()
	macEntry, _ := h.session.MACTable.FindMACNoLock(mac)
	if macEntry == nil {
		h.session.GlobalUnlock()
		return nil
	}
	list := []*packet.Host{}
	list = append(list, macEntry.HostList...)
	macEntry.Captured = false
	h.session.GlobalUnlock()

	for _, host := range list {
		if err := h.lockAndStopHunt(host, packet.StageNormal); err != nil {
			return err
		}
	}
	return nil
}

// lockAndStartHunt controls when to start the hunt process
//
// the following situations are possible:
//   - capture command issued by user
//   - host has come online
//   - icmp ping no longer redirected
func (h *Handler) lockAndStartHunt(addr packet.Addr) (err error) {

	host := h.session.FindIP(addr.IP)
	if host == nil {
		fmt.Printf("packet: error invalid ip in lockAndStartHunt ip=%s\n", addr.IP)
		return packet.ErrInvalidIP
	}

	host.MACEntry.Row.Lock()
	if !host.Online { // host offline, nothing to do
		host.MACEntry.Row.Unlock()
		return nil
	}
	if host.HuntStage == packet.StageHunt {
		host.MACEntry.Row.Unlock()
		return nil
	}
	host.HuntStage = packet.StageHunt
	if packet.Debug {
		fmt.Printf("packet: start hunt for %s\n", host)
	}
	host.MACEntry.Row.Unlock()

	// IP4 handlers
	if addr.IP.To4() != nil {
		go func() {
			if _, err := h.ARPHandler.StartHunt(addr); err != nil {
				fmt.Printf("packet: failed to start arp hunt: %s", err.Error())
			}
			if _, err := h.ICMP4Handler.StartHunt(addr); err != nil {
				fmt.Printf("packet: failed to start icmp4 hunt: %s", err.Error())
			}
			if _, err := h.DHCP4Handler.StartHunt(addr); err != nil {
				fmt.Printf("packet: fai1led to start dhcp4 hunt: %s", err.Error())
			}
		}()
		return nil
	}

	// IP6 handlers
	// Only hunt link local IP
	if !addr.IP.IsLinkLocalUnicast() {
		return nil
	}
	go func() {
		if _, err := h.ICMP6Handler.StartHunt(addr); err != nil {
			fmt.Printf("packet: failed to start icmp6 hunt: %s", err.Error())
		}
	}()
	return nil
}

// lockAndStopHunt will call stop hunting for all plugins
//
// host could be in one of two states:
//  - packet.StageHunt       - an active hunt is in progress
//  - packet.StageRedirected - the host is redirected; typically called when host went offline
//                      or routing is no longer OK
//
func (h *Handler) lockAndStopHunt(host *packet.Host, stage packet.HuntStage) (err error) {
	host.MACEntry.Row.Lock()
	if host.HuntStage != packet.StageHunt {
		host.HuntStage = stage
		host.MACEntry.Row.Unlock()
		return nil
	}

	host.HuntStage = stage
	if packet.Debug {
		fmt.Printf("packet: stop hunt for %s\n", host)
	}

	addr := packet.Addr{MAC: host.MACEntry.MAC, IP: host.Addr.IP}
	host.MACEntry.Row.Unlock()

	// IP4 handlers
	if addr.IP.To4() != nil {
		go func() {
			// DHCP4 will return not found if there is no lease entry; this is okay if the host has not acquired an IP yet
			if _, err := h.DHCP4Handler.StopHunt(addr); err != nil && !errors.Is(err, packet.ErrNotFound) {
				fmt.Printf("packet: failed to stop dhcp4 hunt: %s", err.Error())
			}
			if _, err := h.ICMP4Handler.StopHunt(addr); err != nil {
				fmt.Printf("packet: failed to stop icmp4 hunt: %s", err.Error())
			}
			if _, err := h.ARPHandler.StopHunt(addr); err != nil {
				fmt.Printf("packet: failed to stop arp hunt: %s", err.Error())
			}
		}()
		return nil
	}

	// IP6 handlers
	go func() {
		if _, err := h.ICMP6Handler.StopHunt(addr); err != nil {
			fmt.Printf("packet: failed to stop icmp6 hunt: %s", err.Error())
		}
	}()
	return nil
}

// lockAndSetOnline set the host online and transition activities
//
// This funcion will generate the online event and mark the previous IP4 host as offline if required
//  Parameters:
//     notify: force a notification as another parameter (likely name) has changed
func (h *Handler) lockAndSetOnline(host *packet.Host, notify bool) {
	now := time.Now()
	host.MACEntry.Row.RLock()

	if host.Online && !notify { // just another IP packet - nothing to do
		if now.Sub(host.LastSeen) < time.Second*1 { // update LastSeen every 1 seconds to minimise locking
			host.MACEntry.Row.RUnlock()
			return
		}
	}

	// if transitioning to online, test if we need to make previous IP offline
	offline := []*packet.Host{}
	if !host.Online {
		if host.Addr.IP.To4() != nil {
			if !host.Addr.IP.Equal(host.MACEntry.IP4) { // changed IP4
				fmt.Printf("packet: host changed ip4 mac=%s from=%s to=%s\n", host.MACEntry.MAC, host.MACEntry.IP4, host.Addr.IP)
			}
			for _, v := range host.MACEntry.HostList {
				if ip := v.Addr.IP.To4(); ip != nil && !ip.Equal(host.Addr.IP) {
					offline = append(offline, v)
				}
			}
		} else {
			if host.Addr.IP.IsGlobalUnicast() && !host.Addr.IP.Equal(host.MACEntry.IP6GUA) { // changed IP6 global unique address
				fmt.Printf("packet: host changed ip6 mac=%s from=%s to=%s\n", host.MACEntry.MAC, host.MACEntry.IP6GUA, host.Addr.IP)
				// offlineIP = host.MACEntry.IP6GUA
			}
			if host.Addr.IP.IsLinkLocalUnicast() && !host.Addr.IP.Equal(host.MACEntry.IP6LLA) { // changed IP6 link local address
				fmt.Printf("packet: host changed ip6LLA mac=%s from=%s to=%s\n", host.MACEntry.MAC, host.MACEntry.IP6LLA, host.Addr.IP)
				// don't set offline IP as we don't target LLA
			}
		}
	}

	host.MACEntry.Row.RUnlock()

	// set any previous IP4 to offline
	for _, v := range offline {
		h.lockAndSetOffline(v)
	}

	// lock row for update
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()

	// update LastSeen and current mac IP
	host.MACEntry.LastSeen = now
	host.LastSeen = now
	host.MACEntry.UpdateIPNoLock(host.Addr.IP)

	// return immediately if host already online and not notification
	if host.Online && !notify {
		return
	}

	// if mac is captured, then start hunting process when IP is online
	captured := host.MACEntry.Captured

	host.MACEntry.Online = true
	host.Online = true
	addr := packet.Addr{IP: host.Addr.IP, MAC: host.MACEntry.MAC}
	notification := Notification{Addr: addr, Online: true,
		DHCPName: host.DHCP4Name, MDNSName: host.MDNSName, UPNPName: host.UPNPName,
		Model: host.Model, Manufacturer: host.Manufacturer,
		IsRouter: host.MACEntry.IsRouter}

	if packet.Debug {
		fmt.Printf("packet: IP is online %s\n", host)
	}

	// CAUTION: in goroutine - must not access host fields without lock
	go func() {
		if captured {
			if notification.Addr.IP.To4() != nil {
				// In IPv4 dhcp dictates if host is redirected
				// start hunt if not redirected
				stage, err := h.DHCP4Handler.CheckAddr(addr)
				if err != nil {
					fmt.Printf("packet: failed to get dhcp hunt status %s error=%s\n", addr, err)
				}
				if stage != packet.StageRedirected {
					if err := h.lockAndStartHunt(addr); err != nil {
						fmt.Println("packet: failed to start hunt error", err)
					}
				}
			} else {
				// IPv6 always start hunt
				if err := h.lockAndStartHunt(addr); err != nil {
					fmt.Println("packet: failed to start hunt error", err)
				}
			}
		}
		if h.notificationChannel != nil {
			h.notificationChannel <- notification
		}
	}()
}

func (h *Handler) lockAndSetOffline(host *packet.Host) {
	host.MACEntry.Row.Lock()
	if !host.Online {
		host.MACEntry.Row.Unlock()
		return
	}
	if packet.Debug {
		fmt.Printf("packet: IP is offline %s\n", host)
	}
	host.Online = false
	notification := Notification{Addr: packet.Addr{MAC: host.MACEntry.MAC, IP: host.Addr.IP}, Online: false,
		DHCPName: host.DHCP4Name, MDNSName: host.MDNSName, UPNPName: host.UPNPName,
		Model: host.Model, Manufacturer: host.Manufacturer,
		IsRouter: host.MACEntry.IsRouter}

	// Update mac online status if all hosts are offline
	macOnline := false
	for _, host := range host.MACEntry.HostList {
		if host.Online {
			macOnline = true
			break
		}
	}
	host.MACEntry.Online = macOnline

	host.MACEntry.Row.Unlock()

	h.lockAndStopHunt(host, packet.StageNormal)

	if h.notificationChannel != nil {
		h.notificationChannel <- notification
	}
}

// lockAndProcessDHCP4Update updates the DHCP4 fields and transition to/from hunt stage
//
// Note: typically called with a new IP host and not the previous IP.
//       the new host is likely to be offline and stage normal
func (h *Handler) lockAndProcessDHCP4Update(host *packet.Host, result packet.Result) (notify bool) {
	if host != nil {
		host.MACEntry.Row.Lock()
		if host.DHCP4Name != result.Name {
			host.DHCP4Name = result.Name
			notify = true
		}
		host.MACEntry.Row.Unlock()

		// when selecting or rebooting from another dhcp server,
		// the host will not change state
		if result.HuntStage == packet.StageNoChange {
			return notify
		}

		if err := h.lockAndStopHunt(host, result.HuntStage); err != nil {
			fmt.Printf("packet: failed to stop hunt %s error=\"%s\"", host, err)
		}

		return notify
	}

	// First dhcp discovery has no host entry
	// Ensure there is a mac entry with the IP offer
	if result.FrameAddr.IP != nil && h.session.NICInfo.HostIP4.Contains(result.FrameAddr.IP) {
		entry := h.session.MACTable.FindOrCreateNoLock(result.FrameAddr.MAC)
		entry.IP4Offer = packet.CopyIP(result.FrameAddr.IP)
	}
	return false
}
