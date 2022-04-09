package packet

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/irai/packet/fastlog"
)

// MACEntry stores mac details
// Each host has one MACEntry
type MACEntry struct {
	MAC          net.HardwareAddr // unique mac address
	Captured     bool             // true if mac is in capture mode
	IP4          netip.Addr       // keep current IP4 to detect ip changes
	IP4Offer     netip.Addr       // keep dhcp4 IP offer
	IP6GUA       netip.Addr       // keep current ip6 global unique address
	IP6LLA       netip.Addr       // keep current ip6 local link address
	IP6Offer     netip.Addr       // keep ip6 GUA offer
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
	l := Logger.Msg("")
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
	if e.IP4Offer.IsValid() {
		l.IP("ip4offer", e.IP4Offer)
	}
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
		if e.HostList[i].Addr.IP == host.Addr.IP {
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

// MACTable manages a goroutine safe set for adding and removing mac addresses
type MACTable struct {
	Table []*MACEntry
}

func newMACTable() MACTable {
	return MACTable{Table: []*MACEntry{}}
}

// PrintTable prints the table to stdout
func (h *Session) printMACTable() {
	for _, v := range h.MACTable.Table {
		fmt.Printf("mac %s\n", v)
	}
}

// findOrCreate adds a mac to set
func (s *MACTable) findOrCreate(mac net.HardwareAddr) *MACEntry {
	if e, _ := s.findMAC(mac); e != nil {
		return e
	}
	e := &MACEntry{MAC: CopyMAC(mac), IP4: IPv4zero, IP6GUA: IPv6zero, IP6LLA: IPv6zero, IP4Offer: netip.Addr{}}
	s.Table = append(s.Table, e)
	return e
}

// del deletes the mac from set
func (s *MACTable) delete(mac net.HardwareAddr) error {
	var pos int
	if _, pos = s.findMAC(mac); pos == -1 {
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

func (s *MACTable) findMAC(mac net.HardwareAddr) (*MACEntry, int) {
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
	if n.Expire != (time.Time{}) {
		l.Time("expire", n.Expire)
	}
	return l
}

func (e NameEntry) Merge(nameEntry NameEntry) (newEntry NameEntry, modified bool) {
	if nameEntry.Name != "" && e.Name != nameEntry.Name {
		e.Name = nameEntry.Name
		modified = true
	}
	if nameEntry.Model != "" && e.Model != nameEntry.Model {
		e.Model = nameEntry.Model
		modified = true
	}
	if nameEntry.OS != "" && e.OS != nameEntry.OS {
		e.OS = nameEntry.OS
		modified = true
	}
	if nameEntry.Manufacturer != "" && e.Manufacturer != nameEntry.Manufacturer {
		e.Manufacturer = nameEntry.Manufacturer
		modified = true
	}
	if modified && nameEntry.Expire != (time.Time{}) {
		e.Expire = nameEntry.Expire
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
