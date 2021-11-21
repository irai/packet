package packet

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/irai/packet/fastlog"
)

type Session struct {
	Conn         net.PacketConn
	NICInfo      *NICInfo
	HostTable    HostTable         // store IP list - one for each host
	MACTable     MACTable          // store mac list
	mutex        sync.RWMutex      // global session mutex
	Statisticsts []ProtoStats      // keep per protocol statistics
	C            chan Notification // channel for online & offline notifications
}

func NewSession() *Session {
	session := new(Session)
	session.MACTable = newMACTable()
	session.HostTable = newHostTable()
	session.Statisticsts = make([]ProtoStats, 32)
	session.NICInfo = &NICInfo{HostAddr4: Addr{MAC: EthBroadcast, IP: IP4Broadcast}}
	session.C = make(chan Notification, 128) // plenty of capacity to prevent blocking

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

// NewPacketConn creates a net.PacketConn which can be used to send and receive
// data at the device driver level.
func (h *Session) NewPacketConn(ifi *net.Interface, proto uint16, cfg SocketConfig) (err error) {
	h.Conn, err = NewServerConn(ifi, proto, cfg)
	return err
}

func (h *Session) ReadFrom(b []byte) (int, net.Addr, error) {
	return h.Conn.ReadFrom(b)
}

// SetOnline set the host online and transition activities
//
// This funcion will generate the online event and mark the previous IP4 host as offline if required
func (h *Session) SetOnline(host *Host) {
	if host == nil {
		return
	}
	now := time.Now()
	host.MACEntry.Row.RLock()

	if host.Online && !host.dirty { // just another IP packet - nothing to do
		if now.Sub(host.LastSeen) < time.Second*1 { // update LastSeen every 1 seconds to minimise locking
			host.MACEntry.Row.RUnlock()
			return
		}
	}

	// if transitioning to online, test if we need to make previous IP offline
	offline := []*Host{}
	if !host.Online {
		if host.Addr.IP.To4() != nil {
			if !host.Addr.IP.Equal(host.MACEntry.IP4) { // changed IP4
				fastlog.NewLine(module, "host changed ip4").MAC("mac", host.MACEntry.MAC).IP("from", host.MACEntry.IP4).IP("to", host.Addr.IP).Write()
			}
			for _, v := range host.MACEntry.HostList {
				if ip := v.Addr.IP.To4(); ip != nil && !ip.Equal(host.Addr.IP) {
					offline = append(offline, v)
				}
			}
		} else {
			if host.Addr.IP.IsGlobalUnicast() && !host.Addr.IP.Equal(host.MACEntry.IP6GUA) { // changed IP6 global unique address
				fastlog.NewLine(module, "host changed ip6").MAC("mac", host.MACEntry.MAC).IP("from", host.MACEntry.IP6GUA).IP("to", host.Addr.IP).Write()
				// offlineIP = host.MACEntry.IP6GUA
			}
			if host.Addr.IP.IsLinkLocalUnicast() && !host.Addr.IP.Equal(host.MACEntry.IP6LLA) { // changed IP6 link local address
				fastlog.NewLine(module, "host changed ip6LLA").MAC("mac", host.MACEntry.MAC).IP("from", host.MACEntry.IP6LLA).IP("to", host.Addr.IP).Write()
				// don't set offline IP as we don't target LLA
			}
		}
	}

	host.MACEntry.Row.RUnlock()

	// set any previous IP4 to offline
	for _, v := range offline {
		h.SetOffline(v)
	}

	// lock row for update
	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()

	// update LastSeen and current mac IP
	host.MACEntry.LastSeen = now
	host.LastSeen = now
	host.MACEntry.updateIPNoLock(host.Addr.IP)

	// return immediately if host already online and not notification
	if host.Online && !host.dirty {
		return
	}

	// if mac is captured, then start hunting process when IP is online
	// captured := host.MACEntry.Captured

	host.MACEntry.Online = true
	host.Online = true
	notification := toNotification(host)
	host.dirty = false
	if Debug {
		fastlog.NewLine(module, "IP is online").Struct(host).Write()
	}

	h.sendNotification(notification)
}

func (h *Session) SetOffline(host *Host) {
	host.MACEntry.Row.Lock()
	if !host.Online {
		host.MACEntry.Row.Unlock()
		return
	}
	if Debug {
		fastlog.NewLine(module, "IP is offline").Struct(host).Write()
	}
	host.Online = false
	notification := toNotification(host)

	// Update mac online status if all hosts are offline
	macOnline := false
	for _, host := range host.MACEntry.HostList {
		if host.Online {
			macOnline = true
			break
		}
	}
	host.MACEntry.Online = macOnline
	host.MACEntry.Row.Unlock()

	// h.lockAndStopHunt(host, packet.StageNormal)
	h.sendNotification(notification)
}
