package packet

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type Session struct {
	Conn      net.PacketConn
	NICInfo   *NICInfo
	HostTable HostTable    // store IP list - one for each host
	MACTable  MACTable     // store mac list
	mutex     sync.RWMutex // global session mutex
}

func NewEmptySession() *Session {
	session := new(Session)
	session.MACTable = newMACTable()
	session.HostTable = newHostTable()
	session.NICInfo = &NICInfo{HostAddr4: Addr{MAC: EthBroadcast, IP: IP4Broadcast}}

	// TODO: fix this to discard writes like ioutil.Discard
	session.Conn, _ = net.ListenPacket("udp4", "127.0.0.1:0")

	return session
}

// PacketProcessor defines the interface for packet processing modules
type PacketProcessor interface {
	Start() error
	Stop() error
	ProcessPacket(host *Host, p []byte, header []byte) (Result, error)
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
func (p PacketNOOP) ProcessPacket(*Host, []byte, []byte) (Result, error) {
	return Result{}, nil
}
func (p PacketNOOP) StartHunt(addr Addr) (HuntStage, error) { return StageNoChange, nil }
func (p PacketNOOP) StopHunt(addr Addr) (HuntStage, error)  { return StageNoChange, nil }
func (p PacketNOOP) CheckAddr(addr Addr) (HuntStage, error) { return StageNoChange, nil }
func (p PacketNOOP) Close() error                           { return nil }

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

func (h *Session) GlobalLock() {
	h.mutex.Lock()
}

func (h *Session) GlobalUnlock() {
	h.mutex.Unlock()
}
