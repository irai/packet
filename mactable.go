package packet

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

// MACEntry stores mac details
// Each host has one MACEntry
type MACEntry struct {
	MAC      net.HardwareAddr // unique mac address
	Captured bool             // true if mac is in capture mode
	IP4      net.IP           // keep current IP4 to detect ip changes
	IP4Offer net.IP           // keep dhcp4 IP offer
	IP6      net.IP           // keep current ip6 GUA
	IP6Offer net.IP           // keep ip6 GUA offer
	Online   bool             // true is mac is online
	HostList []*Host          // IPs associated with this mac
	LastSeen time.Time
}

func (e MACEntry) String() string {
	return fmt.Sprintf("mac=%s captured=%v online=%v ip4=%s ip6=%s ip4offer=%s hosts=%d lastSeen=%v",
		e.MAC, e.Captured, e.Online, e.IP4, e.IP6, e.IP4Offer, len(e.HostList), time.Since(e.LastSeen))
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

func (e *MACEntry) updateIP(ip net.IP) {
	if ip.To4() != nil {
		e.IP4 = ip
	} else {
		// TODO: do we need to capture LLA as well?
		if ip.IsGlobalUnicast() {
			e.IP6 = ip
		}
	}
}

// MACTable manages a goroutine safe set for adding and removing mac addresses
type MACTable struct {
	table []*MACEntry
}

func newMACTable(engine *Handler) MACTable {
	return MACTable{table: []*MACEntry{}}
}

// PrintTable prints the table to stdout
func (h *Handler) printMACTable() {
	for _, v := range h.MACTable.table {
		fmt.Println("mac  :", v)
	}
}

// Add adds a mac to set
func (s *MACTable) findOrCreate(mac net.HardwareAddr) *MACEntry {
	if e := s.findMAC(mac); e != nil {
		return e
	}
	e := &MACEntry{MAC: mac}
	s.table = append(s.table, e)
	return e
}

/**
// del deletes the mac from set
func (s *MACTable) delete(mac net.HardwareAddr) error {
	var pos int
	if pos = s.index(mac); pos == -1 {
		return nil
	}

	if pos+1 == len(s.list) { // last element?
		s.list = s.list[:pos]
		return nil
	}
	copy(s.list[pos:], s.list[pos+1:])
	s.list = s.list[:len(s.list)-1]
	return nil
}
**/

// FindMACEntryNoLock returns pointer to macEntry or nil if not found
func (h *Handler) FindMACEntryNoLock(mac net.HardwareAddr) *MACEntry {
	return h.MACTable.findMAC(mac)
}

func (s *MACTable) findMAC(mac net.HardwareAddr) *MACEntry {
	for _, v := range s.table {
		if bytes.Equal(v.MAC, mac) {
			return v
		}
	}
	return nil
}

func (s *MACTable) index(mac net.HardwareAddr) int {
	for i := range s.table {
		if bytes.Equal(s.table[i].MAC, mac) {
			return i
		}
	}
	return -1
}

// MACTableUpsertIP4Offer insert of update mac IP4. Set by dhcp discovery.
func (h *Handler) MACTableUpsertIP4Offer(mac net.HardwareAddr, ip net.IP) {
	h.Lock()
	defer h.Unlock()
	if h.NICInfo.HostIP4.Contains(ip) {
		host, _ := h.findOrCreateHost(mac, ip)
		host.MACEntry.IP4Offer = ip
	}
}

// MACTableGetIP4Offer returns the IP4 associated with this mac.
// Checked by arp ACP
func (h *Handler) MACTableGetIP4Offer(mac net.HardwareAddr) net.IP {
	h.Lock()
	defer h.Unlock()
	if index := h.MACTable.index(mac); index != -1 {
		return h.MACTable.table[index].IP4Offer
	}
	return nil
}
