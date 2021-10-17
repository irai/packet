package packet

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/irai/packet/fastlog"
)

// MACEntry stores mac details
// Each host has one MACEntry
type MACEntry struct {
	MAC          net.HardwareAddr // unique mac address
	Captured     bool             // true if mac is in capture mode
	IP4          net.IP           // keep current IP4 to detect ip changes
	IP4Offer     net.IP           // keep dhcp4 IP offer
	IP6GUA       net.IP           // keep current ip6 global unique address
	IP6LLA       net.IP           // keep current ip6 local link address
	IP6Offer     net.IP           // keep ip6 GUA offer
	Online       bool             // true is mac is online
	IsRouter     bool             // Set to true if this is a router
	HostList     []*Host          // IPs associated with this mac
	Row          sync.RWMutex     // Row level mutex - must lock/unlock if reading/updating MACEntry and Host entry
	Manufacturer string           // Ethernet card manufacturer name
	DHCP4Name    NameEntry
	MDNSName     NameEntry
	SSDPName     NameEntry
	LLMNRName    NameEntry
	NBNSName     NameEntry
	LastSeen     time.Time
}

func (e *MACEntry) String() string {
	l := fastlog.NewLine("", "")
	return e.FastLog(l).ToString()
}

func (e *MACEntry) FastLog(l *fastlog.Line) *fastlog.Line {
	l.MAC("mac", e.MAC)
	if e.Captured {
		l.Bool("captured", e.Captured)
	}
	if e.Online {
		l.Bool("online", e.Online)
	}
	l.IP("ip", e.IP4)
	l.IP("ip6", e.IP6GUA)
	l.IP("lla", e.IP6LLA)
	l.IP("ip4offer", e.IP4Offer)
	l.Int("hosts", len(e.HostList))
	l.String("lastSeen", time.Since(e.LastSeen).String())
	if e.Manufacturer != "" {
		l.String("manufacturer", e.Manufacturer)
	}
	l.Struct(e.DHCP4Name)
	l.Struct(e.MDNSName)
	l.Struct(e.SSDPName)
	l.Struct(e.LLMNRName)
	l.Struct(e.NBNSName)
	return l
}

// link appends the host to the macEntry host list
func (e *MACEntry) link(host *Host) {
	e.HostList = append(e.HostList, host)
}

// unlink removes the Host from the macEntry
func (e *MACEntry) unlink(host *Host) {
	for i := range e.HostList {
		if e.HostList[i].Addr.IP.Equal(host.Addr.IP) {
			if i+1 == len(e.HostList) { // last element?
				e.HostList = e.HostList[:i]
				return
			}
			copy(e.HostList[i:], e.HostList[i+1:])
			e.HostList = e.HostList[:len(e.HostList)-1]
			return
		}
	}
}

func (e *MACEntry) UpdateIPNoLock(ip net.IP) {
	if ip.To4() != nil {
		e.IP4 = ip
	} else {
		if ip.IsGlobalUnicast() {
			e.IP6GUA = ip
		}
		if ip.IsLinkLocalUnicast() {
			e.IP6LLA = ip
		}
	}
}

// MACTable manages a goroutine safe set for adding and removing mac addresses
type MACTable struct {
	Table []*MACEntry
}

func NewMACTable() MACTable {
	return MACTable{Table: []*MACEntry{}}
}

// PrintTable prints the table to stdout
func (h *Session) printMACTable() {
	for _, v := range h.MACTable.Table {
		fmt.Printf("mac %s\n", v)
	}
}

// FindOrCreateNoLock adds a mac to set
func (s *MACTable) FindOrCreateNoLock(mac net.HardwareAddr) *MACEntry {
	if e, _ := s.FindMACNoLock(mac); e != nil {
		return e
	}
	e := &MACEntry{MAC: mac, IP4: net.IPv4zero, IP6GUA: net.IPv6zero, IP6LLA: net.IPv6zero, IP4Offer: net.IPv4zero}
	s.Table = append(s.Table, e)
	return e
}

// del deletes the mac from set
func (s *MACTable) delete(mac net.HardwareAddr) error {
	var pos int
	if _, pos = s.FindMACNoLock(mac); pos == -1 {
		return nil
	}

	if pos+1 == len(s.Table) { // last element?
		s.Table = s.Table[:pos]
		return nil
	}
	copy(s.Table[pos:], s.Table[pos+1:])
	s.Table = s.Table[:len(s.Table)-1]
	return nil
}

// FindMACEntry returns pointer to macEntry or nil if not found
func (h *Session) FindMACEntry(mac net.HardwareAddr) *MACEntry {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	entry, _ := h.MACTable.FindMACNoLock(mac)
	return entry
}

func (s *MACTable) FindMACNoLock(mac net.HardwareAddr) (*MACEntry, int) {
	for pos, v := range s.Table {
		if bytes.Equal(v.MAC, mac) {
			return v, pos
		}
	}
	return nil, -1
}

// NameEntry holds a name entry
type NameEntry struct {
	Type         string
	Name         string
	Model        string
	Manufacturer string
	OS           string
	Expire       time.Time
}

func (n NameEntry) FastLog(l *fastlog.Line) *fastlog.Line {
	if n.Name != "" {
		l.String(n.Type+"name", n.Name)
	}
	if n.Model != "" {
		l.String(n.Type+"model", n.Model)
	}
	if n.OS != "" {
		l.String(n.Type+"OS", n.OS)
	}
	if n.Manufacturer != "" {
		l.String(n.Type+"manufacturer", n.Manufacturer)
	}
	return l
}

func (e NameEntry) Merge(nameEntry NameEntry) (newEntry NameEntry, modified bool) {
	if nameEntry.Name != "" && e.Name != nameEntry.Name {
		e.Name = nameEntry.Name
		e.Expire = nameEntry.Expire
		modified = true
	}
	if nameEntry.Model != "" && e.Model != nameEntry.Model {
		e.Model = nameEntry.Model
		e.Expire = nameEntry.Expire
		modified = true
	}
	if nameEntry.OS != "" && e.OS != nameEntry.OS {
		e.OS = nameEntry.OS
		e.Expire = nameEntry.Expire
		modified = true
	}
	if nameEntry.Manufacturer != "" && e.Manufacturer != nameEntry.Manufacturer {
		e.Manufacturer = nameEntry.Manufacturer
		e.Expire = nameEntry.Expire
		modified = true
	}
	e.Type = nameEntry.Type
	return e, modified
}

// IPNameEntry adds an Address to NameEntry
type IPNameEntry struct {
	Addr      Addr
	NameEntry NameEntry
}

func (n IPNameEntry) FastLog(l *fastlog.Line) *fastlog.Line {
	l.Struct(n.Addr)
	l.Struct(n.NameEntry)
	return l
}
