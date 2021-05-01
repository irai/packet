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
	IP6GUA   net.IP           // keep current ip6 global unique address
	IP6LLA   net.IP           // keep current ip6 local link address
	IP6Offer net.IP           // keep ip6 GUA offer
	Online   bool             // true is mac is online
	isRouter bool             // Set to true if this is a router
	HostList []*Host          // IPs associated with this mac
	LastSeen time.Time
}

func (e MACEntry) String() string {
	return fmt.Sprintf("mac=%s captured=%v online=%v ip4=%s ip6=%s lla=%s ip4offer=%s hosts=%d lastSeen=%v",
		e.MAC, e.Captured, e.Online, e.IP4, e.IP6GUA, e.IP6LLA, e.IP4Offer, len(e.HostList), time.Since(e.LastSeen))
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

func newMACTable(engine *Handler) MACTable {
	return MACTable{Table: []*MACEntry{}}
}

// PrintTable prints the table to stdout
func (h *Handler) printMACTable() {
	for _, v := range h.MACTable.Table {
		fmt.Println("mac  :", v)
	}
}

// Add adds a mac to set
func (s *MACTable) findOrCreate(mac net.HardwareAddr) *MACEntry {
	if e := s.findMAC(mac); e != nil {
		return e
	}
	e := &MACEntry{MAC: mac, IP4: net.IPv4zero, IP6GUA: net.IPv6zero, IP6LLA: net.IPv6zero, IP4Offer: net.IPv4zero}
	s.Table = append(s.Table, e)
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
func (h *Handler) FindMACEntry(mac net.HardwareAddr) *MACEntry {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.MACTable.findMAC(mac)
}

func (s *MACTable) findMAC(mac net.HardwareAddr) *MACEntry {
	for _, v := range s.Table {
		if bytes.Equal(v.MAC, mac) {
			return v
		}
	}
	return nil
}

func (s *MACTable) index(mac net.HardwareAddr) int {
	for i := range s.Table {
		if bytes.Equal(s.Table[i].MAC, mac) {
			return i
		}
	}
	return -1
}

// macTableUpsertIPOffer insert of update mac IP4. Set by dhcp discovery.
func (h *Handler) macTableUpsertIPOffer(addr Addr) {
	if h.NICInfo.HostIP4.Contains(addr.IP) {
		entry := h.MACTable.findOrCreate(addr.MAC)
		entry.IP4Offer = addr.IP
	}
}
