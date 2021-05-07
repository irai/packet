package packet

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type Session struct {
	Conn         net.PacketConn
	NICInfo      *NICInfo
	HostTable    HostTable // store IP list - one for each host
	MACTable     MACTable  // store mac list
	mutex        sync.RWMutex
	eventChannel chan NetEvent
}

func NewEmptySession() *Session {
	session := new(Session)
	session.MACTable = NewMACTable()
	session.HostTable = NewHostTable()
	return session
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
	Close() error
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
func (h *Session) GlobalRLock() {
	h.mutex.RLock()
}

func (h *Session) GlobalRUnlock() {
	h.mutex.RUnlock()
}

// NetEventType defines possible net events
type NetEventType int

const (
	NetEventRouter = 1 // a router event occurred
)

// NetEvent is a mechanism to communicate network events upstream.
//
// A plugins will raise a network event when there is a need to communicate network changes
// to the controlling engine. For example, when the plugin detected a new router on the network.
type NetEvent struct {
	Type NetEventType
	Addr Addr
}

func (n NetEvent) String() string {
	return fmt.Sprintf("type=%d %s", n.Type, n.Addr)
}

func (s *Session) RaiseNetEvent(e NetEvent) error {
	if s.eventChannel == nil {
		return ErrNoReader
	}
	s.eventChannel <- e
	return nil
}

func (s *Session) NetEventChannel() <-chan NetEvent {
	if s.eventChannel == nil {
		s.eventChannel = make(chan NetEvent, 16)
	}
	return s.eventChannel
}
