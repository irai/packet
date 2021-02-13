package packet

import (
	"fmt"
	"net"
	"time"

	"github.com/irai/packet/raw"
)

// Host holds a host identification
type Host struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Online   bool
	LastSeen time.Time
	ICMP4    interface{}
	DHCP4    interface{}
	ICMP6    interface{}
	DHCP6    interface{}
	MDNS     interface{}
	NBNS     interface{}
	ARP      interface{}
}

// PrintTable logs ICMP6 tables to standard out
func (h *Handler) PrintTable() {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if len(h.LANHosts) > 0 {
		fmt.Printf("icmp6 hosts table len=%v\n", len(h.LANHosts))
		for _, v := range h.LANHosts {
			fmt.Printf("mac=%s ip=%v online=%v \n", v.MAC, v.IP, v.Online)
		}
	}
}

func (h *Handler) FindOrCreateHost(mac net.HardwareAddr, ip net.IP) (host *Host, found bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return h.findOrCreateHost(mac, ip)
}

func (h *Handler) findOrCreateHost(mac net.HardwareAddr, ip net.IP) (host *Host, found bool) {
	if host, ok := h.LANHosts[string(ip)]; ok {
		host.LastSeen = time.Now()
		host.Online = true
		return host, true
	}
	host = &Host{MAC: raw.CopyMAC(mac), IP: raw.CopyIP(ip), LastSeen: time.Now(), Online: true}
	h.LANHosts[string(host.IP)] = host
	return host, false
}

func (h *Handler) FindIP(ip net.IP) *Host {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return h.LANHosts[string(ip)]
}

var ipv6LinkLocal = func(cidr string) *net.IPNet {
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return net
}("fe80::/10")
