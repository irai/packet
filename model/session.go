package model

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type Session struct {
	Conn      net.PacketConn
	NICInfo   NICInfo
	HostTable HostTable // store IP list - one for each host
	MACTable  MACTable  // store mac list
	mutex     sync.RWMutex
}

// PacketProcessor defines the interface for packet processing modules
type PacketProcessor interface {
	Start() error
	Stop() error
	ProcessPacket(host *Host, p []byte, header []byte) (*Host, Result, error)
	StartHunt(Addr) (HuntStage, error)
	StopHunt(Addr) (HuntStage, error)
	CheckAddr(Addr) (HuntStage, error)
	MinuteTicker(time.Time) error
}

// PacketNOOP is a no op packet processor
type PacketNOOP struct{}

var _ PacketProcessor = PacketNOOP{}

func (p PacketNOOP) Start() error { return nil }
func (p PacketNOOP) Stop() error  { return nil }
func (p PacketNOOP) ProcessPacket(*Host, []byte, []byte) (*Host, Result, error) {
	return nil, Result{}, nil
}
func (p PacketNOOP) StartHunt(addr Addr) (HuntStage, error) { return StageNoChange, nil }
func (p PacketNOOP) StopHunt(addr Addr) (HuntStage, error)  { return StageNoChange, nil }
func (p PacketNOOP) CheckAddr(addr Addr) (HuntStage, error) { return StageNoChange, nil }

// func (p PacketNOOP) HuntStage(addr Addr) HuntStage              { return StageNormal }
func (p PacketNOOP) MinuteTicker(now time.Time) error { return nil }

// PrintTable logs the table to standard out
func (h *Session) PrintTable() {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	fmt.Printf("mac table len=%d\n", len(h.MACTable.Table))
	h.printMACTable()
	fmt.Printf("hosts table len=%v\n", len(h.HostTable.Table))
	h.printHostTable()
}

// CopyIP simply copies the IP to a new buffer
// Always return len 16 - using go internal 16 bytes for ipv4
func CopyIP(srcIP net.IP) net.IP {
	if len(srcIP) == 4 {
		return srcIP.To16() // this will copy to a new 16 len buffer
	}
	ip := make(net.IP, len(srcIP))
	copy(ip, srcIP)
	return ip
}

// CopyMAC simply copies a mac address to a new buffer with the same len
func CopyMAC(srcMAC net.HardwareAddr) net.HardwareAddr {
	mac := make(net.HardwareAddr, len(srcMAC))
	copy(mac, srcMAC)
	return mac
}

// CopyBytes simply copies a mac address to a new buffer with the same len
func CopyBytes(b []byte) []byte {
	bb := make([]byte, len(b))
	copy(bb, b)
	return bb
}
