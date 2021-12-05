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
	DHCP4Name    NameEntry
	MDNSName     NameEntry
	SSDPName     NameEntry
	LLMNRName    NameEntry
	NBNSName     NameEntry
	dirty        bool
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

// FindOrCreateHost will create a new host entry or return existing
//
// The funcion copies both the mac and the ip; it is safe to call this with a frame.IP(), frame.MAC()
func (h *Session) FindOrCreateHost(addr Addr) (host *Host, found bool) {

	//optimise the common path
	ipNew, _ := netaddr.FromStdIP(addr.IP)
	h.mutex.RLock()
	if host, ok := h.HostTable.Table[ipNew]; ok && bytes.Equal(host.MACEntry.MAC, addr.MAC) {
		h.mutex.RUnlock()
		return host, true
	}
	h.mutex.RUnlock()

	// lock for writing
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return h.findOrCreateHost(addr)
}

// findOrCreateHost find the host using the frame IP (avoid copy if not needed)
//
// Must have engine lock before calling
func (h *Session) findOrCreateHost(addr Addr) (host *Host, found bool) {
	// using netaddr IP
	ipNew, _ := netaddr.FromStdIP(addr.IP)
	now := time.Now()
	if host, ok := h.HostTable.Table[ipNew]; ok {
		host.MACEntry.Row.Lock() // lock the row
		if !bytes.Equal(host.MACEntry.MAC, addr.MAC) {
			fastlog.NewLine(module, "error mac address differ - duplicated IP?").Struct(addr).Struct(host).String("iplookup", ipNew.String()).Write()
			h.printHostTable()
			// TODO: previous host is offline then???
			//       should we send notification?

			// Remove IP from existing mac and link host to new macEntry
			host.MACEntry.unlink(host)
			host.MACEntry.Row.Unlock() // release lock on previous mac

			// Link host to new MACEntry
			macEntry := h.MACTable.FindOrCreateNoLock(CopyMAC(addr.MAC))
			macEntry.Row.Lock()          // acquire lock on new macEntry
			macEntry.link(host)          // link macEntry to host
			host.Addr.MAC = macEntry.MAC // new mac
			host.MACEntry = macEntry     // link host to macEntry
			host.dirty = true            // notify this change
			host.Manufacturer = FindManufacturer(host.Addr.MAC)
			if host.Manufacturer != "" && host.Manufacturer != host.MACEntry.Manufacturer {
				host.MACEntry.Manufacturer = host.Manufacturer
			}
			host.HuntStage = StageNormal // reset stage
		}
		host.LastSeen = now
		host.MACEntry.LastSeen = now
		host.MACEntry.Row.Unlock()
		return host, true
	}
	macEntry := h.MACTable.FindOrCreateNoLock(CopyMAC(addr.MAC))
	host = &Host{Addr: Addr{IP: CopyIP(addr.IP), MAC: macEntry.MAC}, MACEntry: macEntry, dirty: true, Online: false} // set Online to false to trigger Online transition
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

func (h *Session) DeleteHost(ip net.IP) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

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

// IsCaptured returns true is mac is in capture mode
func (h *Session) IsCaptured(mac net.HardwareAddr) bool {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	if e, _ := h.MACTable.FindMACNoLock(mac); e != nil && e.Captured {
		return true
	}
	return false
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

func (host *Host) UpdateLLMNRName(name NameEntry) {
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()
	var notify bool
	host.LLMNRName, notify = host.LLMNRName.Merge(name)
	if notify {
		host.dirty = true
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
		host.dirty = true
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
		host.dirty = true
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
		host.dirty = true
		fastlog.NewLine(module, "updated nbns name").Struct(host.Addr).Struct(host.NBNSName).Write()
		host.MACEntry.NBNSName, _ = host.MACEntry.NBNSName.Merge(host.NBNSName)
	}
}
