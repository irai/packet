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
// when no longer in use. Host pointers are shared with all plugins.
//
// CAUTION:
// Host has a RWMutex used to sync access to the record. This must be read locked to access fields or write locked for updating
// When locking the engine, you must lock the engine first then row lock to avoid deadlocks
type Host struct {
	Addr         Addr      // MAC and IP
	MACEntry     *MACEntry // pointer to mac entry
	Online       bool      // keep host online / offline state
	HuntStage    HuntStage // keep host overall huntStage
	LastSeen     time.Time // keep last packet time
	DHCP4Name    string
	UPNPName     string
	MDNSName     string
	NBNSName     string
	Model        string
	OS           string
	Manufacturer string
}

func (e *Host) String() string {
	line := fastlog.NewLine("", "")
	e.FastLog(line)
	return line.ToString()
}

func (e Host) FastLog(l *fastlog.Line) *fastlog.Line {
	l.MAC("mac", e.Addr.MAC)
	l.IP("ip", e.Addr.IP)
	l.Bool("online", e.Online)
	l.Bool("captured", e.MACEntry.Captured)
	l.String("stage", e.HuntStage.String())
	if e.DHCP4Name != "" {
		l.String("name", e.DHCP4Name)
	}
	if e.MDNSName != "" {
		l.String("mdnsname", e.MDNSName)
	}
	if e.UPNPName != "" {
		l.String("upnpname", e.UPNPName)
	}
	if e.NBNSName != "" {
		l.String("nbnsname", e.NBNSName)
	}
	if e.Model != "" {
		l.String("model", e.Model)
	}
	if e.OS != "" {
		l.String("os", e.OS)
	}
	if e.Manufacturer != "" {
		l.String("manufaturer", e.Manufacturer)
	}
	l.String("lastSeen", time.Since(e.LastSeen).String())
	return l
}

// HuntStage holds the host hunt stage
type HuntStage byte

// possible hunt stages
const (
	StageNoChange   HuntStage = 0 // no change to stage - used as no op
	StageNormal     HuntStage = 1 // not captured
	StageHunt       HuntStage = 2 // host is not redirected
	StageRedirected HuntStage = 3 // host is not redirected
)

func (s HuntStage) String() string {
	if s == StageNormal {
		return "normal"
	}
	if s == StageRedirected {
		return "redirected"
	}
	if s == StageHunt {
		return "hunt"
	}
	return "noop"
}

// Result keeps dhcp4 specific settings
type Result struct {
	Update    bool      // Set to true if update is required
	HuntStage HuntStage // DHCP4 hunt stage
	Name      string    // DHCP4 host name
	FrameAddr Addr      // reference to frame IP and MAC (i.e. not copied) - the engine will copy if required
	IsRouter  bool      // Mark host as router
}

func (e Result) String() string {
	return fmt.Sprintf("huntstage=%s name=%s %s", e.HuntStage, e.Name, e.FrameAddr)
}

// newHostTable returns a HostTable Session
func NewHostTable() HostTable {
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
			fmt.Println("packet: error mac address differ - duplicated IP???", host.MACEntry.MAC, addr.MAC, ipNew)
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
			host.HuntStage = StageNormal // reset stage
			host.DHCP4Name = ""          // clear name from previous host
		}
		host.LastSeen = now
		host.MACEntry.LastSeen = now
		host.MACEntry.Row.Unlock()
		return host, true
	}
	macEntry := h.MACTable.FindOrCreateNoLock(CopyMAC(addr.MAC))
	host = &Host{Addr: Addr{IP: CopyIP(addr.IP), MAC: macEntry.MAC}, MACEntry: macEntry, Online: false} // set Online to false to trigger Online transition
	host.LastSeen = now
	host.HuntStage = StageNormal
	host.MACEntry.LastSeen = now
	// host.MACEntry.UpdateIPNoLock(host.IP)
	h.HostTable.Table[ipNew] = host

	// link host to macEntry
	macEntry.HostList = append(macEntry.HostList, host)
	return host, false
}

func (h *Session) DeleteHost(ip net.IP) {
	if Debug {
		fmt.Printf("packet : delete host ip=%s\n", ip)
	}
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if host := h.findIP(ip); host != nil {
		host.MACEntry.unlink(host)
		newIP, _ := netaddr.FromStdIP(ip)
		delete(h.HostTable.Table, newIP)
		if len(host.MACEntry.HostList) == 0 { // delete if last host
			h.MACTable.delete(host.MACEntry.MAC)
		}
	}
}

// FindIP returns the host entry for IP or nil othewise
func (h *Session) FindIP(ip net.IP) *Host {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	newIP, _ := netaddr.FromStdIP(ip)
	return h.HostTable.Table[newIP]
}

// MustFindIP returns the host for IP or panic if IP is not found
func (h *Session) MustFindIP(ip net.IP) *Host {
	if host := h.FindIP(ip); host != nil {
		return host
	}
	panic(fmt.Sprintf("MustFindIP not found ip=%s", ip))
}

func (h *Session) CaptureNoLock(mac net.HardwareAddr) *MACEntry {
	macEntry := h.MACTable.FindOrCreateNoLock(mac)
	if !macEntry.Captured {
		macEntry.Captured = true
	}
	return macEntry
}

// IsCaptured return true is mac is in capture mode
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

// FindByMAC return a list of IP addresses for mac
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
