package packet

import (
	"bytes"
	"fmt"
	"net"
	"sync"
)

type macDetails struct {
	MAC net.HardwareAddr
	IP4 net.IP
}

// SetHandler manages a goroutine safe set for adding and removing mac addresses
type SetHandler struct {
	list []macDetails
	sync.Mutex
}

// PrintTable prints the table to stdout
func (s *SetHandler) PrintTable() {
	s.Lock()
	defer s.Unlock()
	fmt.Println(s.list)
}

// Add adds a mac to set
func (s *SetHandler) Add(mac net.HardwareAddr) error {
	s.Lock()
	defer s.Unlock()

	if s.index(mac) != -1 {
		return nil
	}
	s.list = append(s.list, macDetails{MAC: mac})
	return nil
}

// Del deletes the mac from set
func (s *SetHandler) Del(mac net.HardwareAddr) error {
	s.Lock()
	defer s.Unlock()

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

// Index returns -1 if mac is not found; otherwise returns the position in set
func (s *SetHandler) Index(mac net.HardwareAddr) int {
	s.Lock()
	defer s.Unlock()
	return s.index(mac)
}

func (s *SetHandler) index(mac net.HardwareAddr) int {
	for i := range s.list {
		if bytes.Equal(s.list[i].MAC, mac) {
			return i
		}
	}
	return -1
}

func (s *SetHandler) UpsertIP4(mac net.HardwareAddr, ip net.IP) {
	s.Lock()
	defer s.Unlock()
	if index := s.index(mac); index != -1 {
		s.list[index].IP4 = ip
		return
	}
	s.list = append(s.list, macDetails{MAC: mac, IP4: ip})
}

func (s *SetHandler) GetIP4(mac net.HardwareAddr) net.IP {
	s.Lock()
	defer s.Unlock()
	if index := s.index(mac); index != -1 {
		return s.list[index].IP4
	}
	return nil
}
