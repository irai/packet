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
	MAC      net.HardwareAddr
	Captured bool
	DHCPIP4  net.IP
	Online   bool
	LastSeen time.Time
}

func (e MACEntry) String() string {
	return fmt.Sprintf("mac=%s captured=%v dhcpIP4=%s Online=%v lastSeen=%v", e.MAC, e.Captured, e.DHCPIP4, e.Online, time.Since(e.LastSeen))
}

// MACTable manages a goroutine safe set for adding and removing mac addresses
type MACTable struct {
	list []*MACEntry
}

func newMACTable(engine *Handler) MACTable {
	return MACTable{list: []*MACEntry{}}
}

// PrintTable prints the table to stdout
func (s *MACTable) printTable() {
	for _, v := range s.list {
		fmt.Println(v)
	}
}

// Add adds a mac to set
func (s *MACTable) add(mac net.HardwareAddr) *MACEntry {
	if e := s.findMAC(mac); e != nil {
		return e
	}
	e := &MACEntry{MAC: mac}
	s.list = append(s.list, e)
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

// FindMACEntry returns pointer to macEntry or nil if not found
func (h *Handler) FindMACEntry(mac net.HardwareAddr) *MACEntry {
	h.Lock()
	defer h.Unlock()
	return h.MACTable.findMAC(mac)
}

func (s *MACTable) findMAC(mac net.HardwareAddr) *MACEntry {
	for _, v := range s.list {
		if bytes.Equal(v.MAC, mac) {
			return v
		}
	}
	return nil
}

func (s *MACTable) index(mac net.HardwareAddr) int {
	for i := range s.list {
		if bytes.Equal(s.list[i].MAC, mac) {
			return i
		}
	}
	return -1
}

// MACTableUpsertIP4 insert of update mac IP4. Set by dhcp discovery.
func (h *Handler) MACTableUpsertIP4(mac net.HardwareAddr, ip net.IP) {
	h.Lock()
	defer h.Unlock()
	if index := h.MACTable.index(mac); index != -1 {
		h.MACTable.list[index].DHCPIP4 = ip
		return
	}
	h.MACTable.list = append(h.MACTable.list, &MACEntry{MAC: mac, DHCPIP4: ip})
}

// MACTableGetIP4 returns the IP4 associated with this mac.
// Checked by arp ACP
func (h *Handler) MACTableGetIP4(mac net.HardwareAddr) net.IP {
	h.Lock()
	defer h.Unlock()
	if index := h.MACTable.index(mac); index != -1 {
		return h.MACTable.list[index].DHCPIP4
	}
	return nil
}
