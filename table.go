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
	IP           net.IP    // either IP6 or ip4
	MACEntry     *MACEntry // pointer to mac entry
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
	return fmt.Sprintf("mac=%s ip=%v online=%v stage4=%s stage6=%s lastSeen=%s", e.MACEntry.MAC, e.IP, e.Online, e.HuntStageIP4, e.HuntStageIP6, time.Since(e.LastSeen))
}

// newHostTable returns a HostTable handler
func newHostTable() HostTable {
	return HostTable{Table: make(map[string]*Host, 64)}
}

// PrintTable logs ICMP6 tables to standard out
func (h *HostTable) printTable() {

	if len(h.Table) > 0 {
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

	return h.findOrCreateHost(mac, ip)
}

// findOrCreateHost find the host associated to the frame IP.
func (h *Handler) findOrCreateHost(mac net.HardwareAddr, ip net.IP) (host *Host, found bool) {

	// trick to avoid buffer allocation in lookup
	// see: net.IPv4() function
	//
	// this function is called for every packet - i.e. VERY often
	var v4InV6Prefix = net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00} // go ipv4 prefix
	if len(ip) == 4 {
		v4InV6Prefix[12] = ip[0]
		v4InV6Prefix[13] = ip[1]
		v4InV6Prefix[14] = ip[2]
		v4InV6Prefix[15] = ip[3]
	} else {
		v4InV6Prefix = ip
	}

	now := time.Now()
	if host, ok := h.LANHosts.Table[string(v4InV6Prefix)]; ok {
		if !bytes.Equal(host.MACEntry.MAC, mac) {
			fmt.Println("packet: error mac address differ - duplicated IP???", host.MACEntry.MAC, mac, v4InV6Prefix)
			// link host to new macEntry
			mac := CopyMAC(mac)
			host.MACEntry.unlink(host) // remove IP from existing mac
			macEntry := h.MACTable.findOrCreate(mac)
			macEntry.link(host)
		}
		host.LastSeen = now
		host.MACEntry.LastSeen = now
		return host, true
	}
	mac = CopyMAC(mac) // copy from frame
	macEntry := h.MACTable.findOrCreate(mac)
	host = &Host{IP: CopyIP(ip), MACEntry: macEntry, Online: false}
	host.LastSeen = now
	host.MACEntry.LastSeen = now
	h.LANHosts.Table[string(host.IP)] = host

	// link host to macEntry
	macEntry.HostList = append(macEntry.HostList, host)
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
		if bytes.Equal(v.MACEntry.MAC, mac) {
			list = append(list, Addr{MAC: v.MACEntry.MAC, IP: v.IP})
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
