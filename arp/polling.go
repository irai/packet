package arp

import (
	"bytes"
	"context"
	"net"
	"time"

	"log"

	"github.com/irai/packet/raw"
)

// pollingLoop detect new IPs on the network
// Send ARP request to all 255 IP addresses first time then send ARP request every so many minutes.
func (c *Handler) scanLoop(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval).C
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker:
			if err := c.ScanNetwork(ctx, c.NICInfo.HomeLAN4); err != nil {
				return err
			}
		}
	}
}

/***
// Probe known macs more often in case they left the network.
func (c *Handler) probeOnlineLoop(ctx context.Context, interval time.Duration) error {
	dur := time.Second * 30
	if interval <= dur {
		dur = interval / 2
	}
	ticker := time.NewTicker(dur).C
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker:
			refreshCutoff := time.Now().Add(interval * -1)

			c.RLock()
			for _, entry := range c.table.macTable {
				if entry.State == StateVirtualHost || !entry.Online {
					continue
				}
				if entry.LastUpdated.Before(refreshCutoff) {
					for _, v := range entry.IPs() {
						if Debug {
							log.Printf("arp ip=%s online? mac=%s", v, entry.MAC)
						}
						if err := c.request(c.NICInfo.HostMAC, c.config.HostIP, entry.MAC, v); err != nil {
							log.Printf("Error ARP request mac=%s ip=%s: %s ", entry.MAC, v, err)
						}
					}
				}
			}
			c.RUnlock()

		}
	}
}
***/

// ScanNetwork sends 256 arp requests to identify IPs on the lan
func (c *Handler) ScanNetwork(ctx context.Context, lan net.IPNet) error {

	// Copy underneath array so we can modify value.
	ip := raw.CopyIP(lan.IP)
	ip = ip.To4()
	if ip == nil {
		return raw.ErrInvalidIP4
	}

	if Debug {
		log.Printf("arp Discovering IP - sending 254 ARP requests - lan %v", lan)
	}
	for host := 1; host < 255; host++ {
		ip[3] = byte(host)

		// Don't scan router and host
		if bytes.Equal(ip, c.NICInfo.RouterIP4.IP) || bytes.Equal(ip, c.NICInfo.HostIP4.IP) {
			continue
		}

		err := c.request(c.NICInfo.HostMAC, c.NICInfo.HostIP4.IP, EthernetBroadcast, ip)
		if ctx.Err() == context.Canceled {
			return nil
		}
		if err != nil {
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				if Debug {
					log.Print("arp error in write socket is temporary - retry ", err1)
				}
				continue
			}

			if Debug {
				log.Print("arp request error ", err)
			}
			return err
		}
		time.Sleep(time.Millisecond * 8)
	}

	return nil
}
