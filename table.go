package packet

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

// HostTable manages host entries
type HostTable struct {
	Table map[string]*Host
}

// HuntStage holds the host hunt stage
type HuntStage byte

// possible hunt stages
const (
	StageNormal     HuntStage = 0 // not captured
	StageHunt       HuntStage = 1 // host is not redirected
	StageRedirected HuntStage = 2 // host is not redirected
)

func (s HuntStage) String() string {
	if s == StageNormal {
		return "normal"
	}
	if s == StageHunt {
		return "hunt"
	}
	return "redirected"
}

// Host holds a host identification
type Host struct {
	MAC          net.HardwareAddr
	IP           net.IP
	Online       bool
	IPV6Router   bool
	HuntStageIP4 HuntStage
	HuntStageIP6 HuntStage
	LastSeen     time.Time
	ICMP4        interface{}
	DHCP4        interface{}
	ICMP6        interface{}
	DHCP6        interface{}
	MDNS         interface{}
	NBNS         interface{}
	ARP          interface{}
}

func (e *Host) String() string {
	return fmt.Sprintf("mac=%s ip=%v online=%v stage4=%s stage6=%s lastSeen=%s", e.MAC, e.IP, e.Online, e.HuntStageIP4, e.HuntStageIP6, time.Since(e.LastSeen))
}

// newHostTable returns a HostTable handler
func newHostTable() HostTable {
	return HostTable{Table: make(map[string]*Host, 64)}
}

// PrintTable logs ICMP6 tables to standard out
func (h *HostTable) printTable() {

	if len(h.Table) > 0 {
		fmt.Printf("hosts table len=%v\n", len(h.Table))
		for _, v := range h.Table {
			fmt.Println(v)
		}
	}
}

// FindOrCreateHost will create a new host entry or return existing
//
// The funcion copies both the mac and the ip; it is safe to call this with a frame.IP(), frame.MAC()
func (h *Handler) FindOrCreateHost(mac net.HardwareAddr, ip net.IP) (host *Host, found bool) {
	h.Lock()
	defer h.Unlock()

	return h.LANHosts.findOrCreateHost(mac, ip)
}

func (h *HostTable) findOrCreateHost(mac net.HardwareAddr, ip net.IP) (host *Host, found bool) {

	// trick to avoid buffer allocation in lookup
	// see: net.IPv4() function
	//
	// this function is called VERY often
	var v4InV6Prefix = net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00} // go ipv4 prefix
	if len(ip) == 4 {
		v4InV6Prefix[12] = ip[0]
		v4InV6Prefix[13] = ip[1]
		v4InV6Prefix[14] = ip[2]
		v4InV6Prefix[15] = ip[3]
	} else {
		v4InV6Prefix = ip
	}

	if host, ok := h.Table[string(v4InV6Prefix)]; ok {
		if !bytes.Equal(host.MAC, mac) {
			fmt.Println("packet: error mac address differ", host.MAC, mac, v4InV6Prefix)
			host.MAC = CopyMAC(mac)
		}
		host.LastSeen = time.Now()
		return host, true
	}
	host = &Host{MAC: CopyMAC(mac), IP: CopyIP(ip), LastSeen: time.Now(), Online: false}
	h.Table[string(host.IP)] = host
	return host, false
}

// FindIP returns the host entry for IP or nil othewise
func (h *Handler) FindIP(ip net.IP) *Host {
	h.Lock()
	defer h.Unlock()

	return h.LANHosts.Table[string(ip.To16())]
}

// FindIPNoLock finds the host for IP wihout locking the engine
// Engine must be locked prior to calling this function
func (h *Handler) FindIPNoLock(ip net.IP) *Host {
	return h.LANHosts.Table[string(ip.To16())]
}

// FindByMAC return a list of IP addresses for mac
func (h *Handler) FindByMAC(mac net.HardwareAddr) (list []Addr) {
	h.Lock()
	defer h.Unlock()
	for _, v := range h.LANHosts.Table {
		if bytes.Equal(v.MAC, mac) {
			list = append(list, Addr{MAC: v.MAC, IP: v.IP})
		}
	}
	return list
}

// GetTable returns a copy of the current table
func (h *Handler) GetTable() (list []Host) {
	h.Lock()
	defer h.Unlock()
	list = make([]Host, len(h.LANHosts.Table))
	for _, v := range h.LANHosts.Table {
		list = append(list, *v)
	}
	return list
}

func (h *HostTable) delete(ip net.IP) {
	delete(h.Table, string(ip))
}
