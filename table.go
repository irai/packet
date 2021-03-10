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
	IP         net.IP    // either IP6 or ip4
	MACEntry   *MACEntry // pointer to mac entry
	Online     bool
	IPV6Router bool
	HuntStage  HuntStage
	LastSeen   time.Time
	ICMP4      interface{}
	DHCP4      interface{}
	ICMP6      interface{}
	DHCP6      interface{}
	MDNS       interface{}
	NBNS       interface{}
	ARP        interface{}
}

func (e *Host) String() string {
	return fmt.Sprintf("mac=%s ip=%v online=%v stage4=%s lastSeen=%s", e.MACEntry.MAC, e.IP, e.Online, e.HuntStage, time.Since(e.LastSeen))
}

// newHostTable returns a HostTable handler
func newHostTable() HostTable {
	return HostTable{Table: make(map[string]*Host, 64)}
}

// PrintTable logs ICMP6 tables to standard out
func (h *Handler) printHostTable() {
	count := 0
	for _, v := range h.MACTable.table {
		for _, host := range v.HostList {
			fmt.Println("host :", host)
			count++
		}
	}
	if count != len(h.LANHosts.Table) { // validate our logic - DELETE and replace with test in future
		panic(fmt.Sprintf("host table differ in lenght hosts=%d machosts=%d  ", len(h.LANHosts.Table), count))
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

// findOrCreateHost find the host using the frame IP (avoid copy if not needed)
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
			h.printHostTable()
			// link host to new macEntry
			mac := CopyMAC(mac)
			host.MACEntry.unlink(host) // remove IP from existing mac
			macEntry := h.MACTable.findOrCreate(mac)
			macEntry.updateIP(host.IP)
			macEntry.link(host)
			host.MACEntry = macEntry
		}
		host.LastSeen = now
		host.MACEntry.LastSeen = now
		return host, true
	}
	mac = CopyMAC(mac) // copy from frame
	macEntry := h.MACTable.findOrCreate(mac)
	host = &Host{IP: CopyIP(ip), MACEntry: macEntry, Online: false} // set Online to false to trigger Online transition
	host.LastSeen = now
	host.MACEntry.LastSeen = now
	if ip.To4() != nil {
		host.MACEntry.IP4 = ip
	} else {
		// TODO: do we need to capture LLA as well?
		if ip.IsGlobalUnicast() {
			host.MACEntry.IP6 = ip
		}
	}
	h.LANHosts.Table[string(host.IP)] = host

	// link host to macEntry
	macEntry.HostList = append(macEntry.HostList, host)
	return host, false
}

func (h *Handler) deleteHostWithLock(ip net.IP) {
	h.Lock()
	defer h.Unlock()

	if host := h.FindIPNoLock(ip); host != nil {
		host.MACEntry.unlink(host)
		delete(h.LANHosts.Table, string(host.IP))
	}
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
