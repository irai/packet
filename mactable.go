package packet

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// MACEntry stores mac details
// Each host has one MACEntry
type MACEntry struct {
	MAC      net.HardwareAddr // unique mac address
	Captured bool             // true if mac is in capture mode
	IP4      net.IP           // keep current IP4 to detect ip changes
	IP4Offer net.IP           // keep dhcp4 IP offer
	IP6GUA   net.IP           // keep current ip6 global unique address
	IP6LLA   net.IP           // keep current ip6 local link address
	IP6Offer net.IP           // keep ip6 GUA offer
	Online   bool             // true is mac is online
	IsRouter bool             // Set to true if this is a router
	HostList []*Host          // IPs associated with this mac
	Row      sync.RWMutex     // Row level mutex
	LastSeen time.Time
}

func (e *MACEntry) String() string {
	// return fmt.Sprintf("mac=%s captured=%v online=%v ip4=%s ip6=%s lla=%s ip4offer=%s hosts=%d lastSeen=%s",
	// e.MAC, e.Captured, e.Online, e.IP4, e.IP6GUA, e.IP6LLA, e.IP4Offer, len(e.HostList), time.Since(e.LastSeen))
	var b strings.Builder
	b.Grow(120)
	b.WriteString("mac=")
	b.WriteString(e.MAC.String())
	if e.Captured {
		b.WriteString(" captured=true")
	} else {
		b.WriteString(" captured=false")
	}
	if e.Online {
		b.WriteString(" online=true ip4=")
	} else {
		b.WriteString(" online=false ip4=")
	}
	b.WriteString(e.IP4.String())
	b.WriteString(" ip6=")
	b.WriteString(e.IP6GUA.String())
	b.WriteString(" lla=")
	b.WriteString(e.IP6LLA.String())
	b.WriteString(" ip4offer=")
	b.WriteString(e.IP4Offer.String())
	b.WriteString(" hosts=")
	b.WriteByte((byte(len(e.HostList)))) // truncate to single byte
	b.WriteString(" lastSeen=")
	b.WriteString(time.Since(e.LastSeen).String())
	return b.String()
}

// link appends the host to the macEntry host list
func (e *MACEntry) link(host *Host) {
	e.HostList = append(e.HostList, host)
}

// unlink removes the Host from the macEntry
func (e *MACEntry) unlink(host *Host) {
	for i := range e.HostList {
		if e.HostList[i].IP.Equal(host.IP) {
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
		fmt.Printf("packet: mac entry %s\n", v)
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
