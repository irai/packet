package arp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/irai/packet"
)

// ScanNetwork sends 256 arp requests to identify IPs on the lan
func (h *Handler) ScanNetwork(ctx context.Context, lan net.IPNet) error {

	// Copy underneath array so we can modify value.
	ip := packet.CopyIP(lan.IP)
	ip = ip.To4()
	if ip == nil {
		return packet.ErrInvalidIP
	}

	if Debug {
		fmt.Printf("arp   : scan - sending 254 ARP requests - lan %v", lan)
	}
	for host := 1; host < 255; host++ {
		ip[3] = byte(host)

		// Don't scan router and host
		if ip.Equal(h.session.NICInfo.RouterIP4.IP) || ip.Equal(h.session.NICInfo.HostIP4.IP) {
			continue
		}

		err := h.session.Request(ip)
		if ctx.Err() == context.Canceled {
			return nil
		}
		if err != nil {
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				if Debug {
					fmt.Println("arp   : error in write socket is temporary - retry ", err1)
				}
				continue
			}

			if Debug {
				fmt.Println("arp   : request error ", err)
			}
			return err
		}
		time.Sleep(time.Millisecond * 8)
	}

	return nil
}
