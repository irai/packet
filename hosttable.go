package packet

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/irai/packet/fastlog"
	"inet.af/netaddr"
)

// HostTable manages host entries
type HostTable struct {
	Table map[netaddr.IP]*Host
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
	flags        uint      // processing flags : dirty(0x01), online_transition (0x02), offline_transition (0x04)
	DHCP4Name    NameEntry
	MDNSName     NameEntry
	SSDPName     NameEntry
	LLMNRName    NameEntry
	NBNSName     NameEntry
	// dirty        bool
}

func (e *Host) dirty() bool { return e.flags&0x01 == 0x01 }
func (e *Host) setDirty(b bool) {
	if b {
		e.flags |= 0b001
	} else {
		e.flags &= 0b110
	}
}

func (e *Host) onlineTransition() bool { return e.flags&0x02 == 0x02 }
func (e *Host) setOnlineTransition(b bool) {
	if b {
		e.flags |= 0b010
	} else {
		e.flags &= 0b101
	}
}

func (e *Host) offlineTransition() bool { return e.flags&0x04 == 0x04 }
func (e *Host) setOfflineTransition(b bool) {
	if b {
		e.flags |= 0b100
	} else {
		e.flags &= 0b011
	}
}

func (e *Host) String() string {
	return fastlog.NewLine("", "").Struct(e).ToString()
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

func (e Result) String() string {
	return fmt.Sprintf("huntstage=%s name=%s %s", e.HuntStage, e.NameEntry, e.SrcAddr)
}

// newHostTable returns a HostTable Session
func newHostTable() HostTable {
	return HostTable{Table: make(map[netaddr.IP]*Host, 64)}
}

// PrintTable print table to standard out
func (h *Session) printHostTable() {
	count := 0
	for _, v := range h.MACTable.Table {
		for _, host := range v.HostList {
			fastlog.NewLine("packet", "host").Struct(host).Write()
			count++
		}
	}
	if count != len(h.HostTable.Table) { // validate our logic - DELETE and replace with test in future
		panic(fmt.Sprintf("host table differ in lenght hosts=%d machosts=%d  ", len(h.HostTable.Table), count))
	}
}

// findOrCreateHostWithLock will create a new host entry or return existing
//
// The funcion copies both the mac and the ip; it is safe to call this with a frame.IP(), frame.MAC()
func (h *Session) findOrCreateHostWithLock(addr Addr) (host *Host, found bool) {

	//optimise the common path
	ipNew, _ := netaddr.FromStdIP(addr.IP)
	h.mutex.RLock()
	if host, ok := h.HostTable.Table[ipNew]; ok && bytes.Equal(host.MACEntry.MAC, addr.MAC) {
		h.mutex.RUnlock()
		return host, true
	}
	h.mutex.RUnlock()

	// lock session for writing
	h.mutex.Lock()
	defer h.mutex.Unlock()

	now := time.Now()
	if host, ok := h.HostTable.Table[ipNew]; ok {
		deleteHost := false
		host.MACEntry.Row.Lock() // lock the row
		if !bytes.Equal(host.MACEntry.MAC, addr.MAC) {
			deleteHost = true
		}
		host.MACEntry.Row.Unlock() // lock the row

		if deleteHost {
			fastlog.NewLine(module, "error mac address differ - duplicated IP?").Struct(addr).Struct(host).String("iplookup", ipNew.String()).Write()
			h.printHostTable()
			h.deleteHost(addr.IP)
			// TODO: previous host is offline then???
			//       should we send notification?
		}
	}

	macEntry := h.MACTable.findOrCreate(CopyMAC(addr.MAC))
	host = &Host{Addr: Addr{IP: CopyIP(addr.IP), MAC: macEntry.MAC}, MACEntry: macEntry, Online: false} // set Online to false to trigger Online transition
	host.setDirty(true)
	host.Manufacturer = FindManufacturer(macEntry.MAC)
	if host.Manufacturer != "" && host.Manufacturer != host.MACEntry.Manufacturer {
		host.MACEntry.Manufacturer = host.Manufacturer
	}
	host.HuntStage = StageNormal
	host.LastSeen = now
	host.MACEntry.LastSeen = now
	h.HostTable.Table[ipNew] = host

	// link host to macEntry
	macEntry.HostList = append(macEntry.HostList, host)
	return host, false
}

func (h *Session) deleteHost(ip net.IP) {
	if host := h.findIP(ip); host != nil {
		if Debug {
			fastlog.NewLine(module, "delete host").IP("ip", ip).Struct(host).Write()
		}
		host.MACEntry.unlink(host)
		newIP, _ := netaddr.FromStdIP(ip)
		delete(h.HostTable.Table, newIP)
		if len(host.MACEntry.HostList) == 0 { // delete if last host
			h.MACTable.delete(host.MACEntry.MAC)
		}
		return
	}
	if Debug {
		fastlog.NewLine(module, "delete host IP not found").IP("ip", ip).Write()
	}
}

// FindIP returns the host entry for IP or nil othewise
func (h *Session) FindIP(ip net.IP) *Host {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	newIP, _ := netaddr.FromStdIP(ip)
	return h.HostTable.Table[newIP]
}

// findIP finds the host for IP wihout locking the engine
// Engine must be locked prior to calling this function
func (h *Session) findIP(ip net.IP) *Host {
	newIP, _ := netaddr.FromStdIP(ip)
	return h.HostTable.Table[newIP]
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
		host.setDirty(true)
		fastlog.NewLine(module, "updated dhcpv4 name").Struct(host.Addr).Struct(host.DHCP4Name).Write()
		host.MACEntry.DHCP4Name, _ = host.MACEntry.DHCP4Name.Merge(host.DHCP4Name)
	}
}

func (host *Host) UpdateLLMNRName(name NameEntry) {
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()
	var notify bool
	host.LLMNRName, notify = host.LLMNRName.Merge(name)
	if notify {
		host.setDirty(true)
		fastlog.NewLine(module, "updated llmnr name").Struct(host.Addr).Struct(host.LLMNRName).Write()
		host.MACEntry.LLMNRName, _ = host.MACEntry.LLMNRName.Merge(host.LLMNRName)
	}
}

func (host *Host) UpdateMDNSName(name NameEntry) {
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()
	var notify bool
	host.MDNSName, notify = host.MDNSName.Merge(name)
	if notify {
		host.setDirty(true)
		fastlog.NewLine(module, "updated mdns name").Struct(host.Addr).Struct(host.MDNSName).Write()
		host.MACEntry.MDNSName, _ = host.MACEntry.MDNSName.Merge(host.MDNSName)
	}
}

func (host *Host) UpdateSSDPName(name NameEntry) {
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()
	var notify bool
	host.SSDPName, notify = host.SSDPName.Merge(name)
	if notify {
		host.setDirty(true)
		fastlog.NewLine(module, "updated ssdp name").Struct(host.Addr).Struct(host.SSDPName).Write()
		host.MACEntry.SSDPName, _ = host.MACEntry.SSDPName.Merge(host.SSDPName)
	}
}

func (host *Host) UpdateNBNSName(name NameEntry) {
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()
	var notify bool
	host.NBNSName, notify = host.NBNSName.Merge(name)
	if notify {
		host.setDirty(true)
		fastlog.NewLine(module, "updated nbns name").Struct(host.Addr).Struct(host.NBNSName).Write()
		host.MACEntry.NBNSName, _ = host.MACEntry.NBNSName.Merge(host.NBNSName)
	}
}
