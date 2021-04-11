package packet

import (
	"bytes"
	"fmt"
	"net"
)

var _ net.Addr = &Addr{}

// Addr is a network address which can be used to contact other machines, using
// their hardware addresses.
type Addr struct {
	MAC  net.HardwareAddr
	IP   net.IP
	Port uint16
}

// String returns the address's hardware address.
func (a Addr) String() string {
	if a.Port == 0 {
		return fmt.Sprintf("mac=%s ip=%s", a.MAC, a.IP)
	}
	return fmt.Sprintf("mac=%s ip=%s port=%d", a.MAC, a.IP, a.Port)
}

// Network returns the address's network name, "raw".
func (a Addr) Network() string {
	return "raw"
}

// AddrList manages a goroutine safe set for adding and removing mac addresses
type AddrList struct {
	list []Addr
}

// Add adds a mac to set
func (s *AddrList) Add(addr Addr) error {

	if s.index(addr.MAC) != -1 {
		return nil
	}
	s.list = append(s.list, addr)
	return nil
}

// Del deletes the mac from set
func (s *AddrList) Del(addr Addr) error {

	var pos int
	if pos = s.index(addr.MAC); pos == -1 {
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

// Index returns -1 if mac is not found; otherwise returns the position in set
func (s *AddrList) Index(mac net.HardwareAddr) int {
	return s.index(mac)
}

func (s *AddrList) index(mac net.HardwareAddr) int {
	for i := range s.list {
		if bytes.Equal(s.list[i].MAC, mac) {
			return i
		}
	}
	return -1
}
