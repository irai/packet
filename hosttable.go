package packet

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"net/netip"

	"github.com/irai/packet/fastlog"
)

// HostTable manages host entries
type HostTable struct {
	Table map[netip.Addr]*Host
}

// Host holds a pointer to the host record. The pointer is always valid and will be garbage collected
// when no longer in use.
//
// CAUTION:
// Host has a RWMutex used to sync access to the record. This must be read locked to access fields or write locked for updating
// When locking the engine, you must lock the engine first then row lock to avoid deadlocks
type Host struct {
	Addr         Addr      // MAC and IP
	MACEntry     *MACEntry // pointer to mac entry
	Online       bool      // host online / offline state
	HuntStage    HuntStage // host huntStage
	LastSeen     time.Time // last packet time
	Manufacturer string    // Mac address manufacturer
	DHCP4Name    NameEntry
	MDNSName     NameEntry
	SSDPName     NameEntry
	LLMNRName    NameEntry
	NBNSName     NameEntry
	dirty        bool
}

func (e *Host) String() string {
	return Logger.Msg("").Struct(e).ToString()
}

func (e Host) FastLog(l *fastlog.Line) *fastlog.Line {
	l.MAC("mac", e.Addr.MAC)
	l.IP("ip", e.Addr.IP)
	l.Bool("online", e.Online)
	l.Bool("captured", e.MACEntry.Captured)
	l.String("stage", e.HuntStage.String())
	l.String("manufacturer", e.Manufacturer)
	l.Struct(e.DHCP4Name)
	l.Struct(e.MDNSName)
	l.Struct(e.SSDPName)
	l.Struct(e.LLMNRName)
	l.Struct(e.NBNSName)
	l.String("lastSeen", time.Since(e.LastSeen).String())
	return l
}

// HuntStage holds the host hunt stage
type HuntStage byte

// hunt stages
const (
	StageNoChange   HuntStage = 0 // no change to stage - used as no op
	StageNormal     HuntStage = 1 // not captured
	StageHunt       HuntStage = 2 // host is not redirected
	StageRedirected HuntStage = 3 // host is redirected via dhcp
)

func (s HuntStage) String() string {
	switch s {
	case StageNormal:
		return "normal"
	case StageRedirected:
		return "redirected"
	case StageHunt:
		return "hunt"
	}
	return "noop"
}

// newHostTable returns a HostTable Session
func newHostTable() HostTable {
	return HostTable{Table: make(map[netip.Addr]*Host, 64)}
}

// PrintTable print table to standard out
func (h *Session) printHostTable() {
	count := 0
	for _, v := range h.MACTable.Table {
		for _, host := range v.HostList {
			Logger.Msg("host").Struct(host).Write()
			count++
		}
	}
	if count != len(h.HostTable.Table) { // validate our logic - DELETE and replace with test in future
		panic(fmt.Sprintf("host table differ in lenght hosts=%d machosts=%d  ", len(h.HostTable.Table), count))
	}
}

// Dirty returns true if the host was updated by Parse and a notification is due.
func (host *Host) Dirty() bool {
	return host.dirty
}

// findOrCreateHostWithLock will create a new host entry or return existing and
// it will update the LastSeen time
//
// The funcion copies both the mac and it iss safe to call this with a packet buffer slice.
func (h *Session) findOrCreateHostWithLock(addr Addr) (host *Host, found bool) {
	now := time.Now()
	//optimise the common path
	h.mutex.RLock()
	if host, found = h.HostTable.Table[addr.IP]; found && bytes.Equal(host.MACEntry.MAC, addr.MAC) {
		host.LastSeen = now
		host.MACEntry.LastSeen = now
		h.mutex.RUnlock()
		return host, true
	}
	h.mutex.RUnlock()

	// lock session for writing
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// if host exist in table but has different mac address,
	// we need to remove the existing link host->mac and create a fresh link.
	if host != nil {
		Logger.Msg("error mac address differ - duplicated IP?").Struct(addr).Struct(host).IP("iplookup", addr.IP).Write()
		h.printHostTable()
		h.deleteHost(addr.IP)
		// TODO: previous host is offline then???
		//       should we send notification?
	}

	// this is new IP,
	// create a new host and link to mac entry
	macEntry := h.MACTable.findOrCreate(addr.MAC)
	host = &Host{Addr: Addr{IP: addr.IP, MAC: macEntry.MAC}, MACEntry: macEntry, Online: false} // set to false to trigger Online transition
	host.dirty = true
	host.Manufacturer = FindManufacturer(macEntry.MAC)
	if host.Manufacturer != "" && host.Manufacturer != host.MACEntry.Manufacturer {
		host.MACEntry.Manufacturer = host.Manufacturer
	}
	host.HuntStage = StageNormal
	host.LastSeen = now
	host.MACEntry.LastSeen = now
	h.HostTable.Table[addr.IP] = host

	// link host to macEntry
	macEntry.HostList = append(macEntry.HostList, host)
	return host, false
}

func (h *Session) deleteHost(ip netip.Addr) {
	// newIP, _ := netip.AddrFromSlice(ip)
	if host := h.findIP(ip); host != nil {
		if Logger.IsDebug() {
			Logger.Msg("delete host").IP("ip", ip).Struct(host).Write()
		}
		host.MACEntry.unlink(host)
		delete(h.HostTable.Table, ip)
		if len(host.MACEntry.HostList) == 0 { // delete if last host
			h.MACTable.delete(host.MACEntry.MAC)
		}
		return
	}
	if Logger.IsDebug() {
		Logger.Msg("delete host IP not found").IP("ip", ip).Write()
	}
}

// FindIP returns the host entry for IP or nil othewise
func (h *Session) FindIP(ip netip.Addr) *Host {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	// newIP, _ := netip.AddrFromSlice(ip)
	return h.HostTable.Table[ip]
}

// findIP finds the host for IP wihout locking the engine
// Engine must be locked prior to calling this function
func (h *Session) findIP(ip netip.Addr) *Host {
	// newIP, ok := netip.AddrFromSlice(ip)
	// fmt.Println("TRACE ", newIP)
	// if !ok {
	// panic(fmt.Sprintf("invalid ip %v", ip))
	// }
	return h.HostTable.Table[ip]
}

// FindByMAC returns a list of IP addresses for mac
func (h *Session) FindByMAC(mac net.HardwareAddr) (list []Addr) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	for _, v := range h.HostTable.Table {
		if bytes.Equal(v.MACEntry.MAC, mac) {
			list = append(list, Addr{MAC: v.MACEntry.MAC, IP: v.Addr.IP})
		}
	}
	return list
}

// GetTable returns a shallow copy of the current table
func (h *Session) GetHosts() (list []*Host) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	list = make([]*Host, 0, len(h.HostTable.Table))
	for _, v := range h.HostTable.Table {
		list = append(list, v)
	}
	return list
}

func (host *Host) UpdateDHCP4Name(name NameEntry) {
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()
	var notify bool
	host.DHCP4Name, notify = host.DHCP4Name.Merge(name)
	if notify {
		host.dirty = true
		Logger.Msg("updated dhcpv4 name").Struct(host.Addr).Struct(host.DHCP4Name).Write()
		host.MACEntry.DHCP4Name, _ = host.MACEntry.DHCP4Name.Merge(host.DHCP4Name)
	}
}

func (host *Host) UpdateLLMNRName(name NameEntry) {
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()
	var notify bool
	host.LLMNRName, notify = host.LLMNRName.Merge(name)
	if notify {
		host.dirty = true
		Logger.Msg("updated llmnr name").Struct(host.Addr).Struct(host.LLMNRName).Write()
		host.MACEntry.LLMNRName, _ = host.MACEntry.LLMNRName.Merge(host.LLMNRName)
	}
}

func (host *Host) UpdateMDNSName(name NameEntry) {
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()
	var notify bool
	host.MDNSName, notify = host.MDNSName.Merge(name)
	if notify {
		host.dirty = true
		Logger.Msg("updated mdns name").Struct(host.Addr).Struct(host.MDNSName).Write()
		host.MACEntry.MDNSName, _ = host.MACEntry.MDNSName.Merge(host.MDNSName)
	}
}

func (host *Host) UpdateSSDPName(name NameEntry) {
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()
	var notify bool
	host.SSDPName, notify = host.SSDPName.Merge(name)
	if notify {
		host.dirty = true
		Logger.Msg("updated ssdp name").Struct(host.Addr).Struct(host.SSDPName).Write()
		host.MACEntry.SSDPName, _ = host.MACEntry.SSDPName.Merge(host.SSDPName)
	}
}

func (host *Host) UpdateNBNSName(name NameEntry) {
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()
	var notify bool
	host.NBNSName, notify = host.NBNSName.Merge(name)
	if notify {
		host.dirty = true
		Logger.Msg("updated nbns name").Struct(host.Addr).Struct(host.NBNSName).Write()
		host.MACEntry.NBNSName, _ = host.MACEntry.NBNSName.Merge(host.NBNSName)
	}
}
