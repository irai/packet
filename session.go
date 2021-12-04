package packet

import (
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/irai/packet/fastlog"
)

type Session struct {
	Conn            net.PacketConn
	NICInfo         *NICInfo
	OfflineDeadline time.Duration     // mark Host offline if no traffic for this long
	PurgeDeadline   time.Duration     // delete Host if no traffic for this long
	HostTable       HostTable         // store IP list - one for each host
	ipHeartBeat     uint32            // ipHeartBeat is set to 1 when we receive an IP packet
	MACTable        MACTable          // store mac list
	mutex           sync.RWMutex      // global session mutex
	Statisticsts    []ProtoStats      // keep per protocol statistics
	C               chan Notification // channel for online & offline notifications
	closeChan       chan bool         // channel to end all go routines
}

// Config contains configurable parameters that overide package defaults
type Config struct {
	// Conn enables the client to override the connection with a another packet conn
	// useful for testing
	Conn            net.PacketConn // override connection
	NICInfo         *NICInfo       // override nic information - set to non nil to create a test Handler
	OfflineDeadline time.Duration  // override offline deadline
	PurgeDeadline   time.Duration  // override purge deadline
}

// Default dealines
const (
	DefaultOfflineDeadline = time.Minute * 5
	DefaultPurgeDeadline   = time.Hour
)

// monitorNICFrequency defines how often to check for nick heart beat
var monitorNICFrequency = time.Minute * 3

func NewSession(nic string) (*Session, error) {
	nicinfo, err := GetNICInfo(nic)
	if err != nil {
		fmt.Printf("interface not found nic=%s: %s\n", nic, err)
		return nil, err
	}
	conn, err := NewServerConn(nicinfo.IFI, syscall.ETH_P_ALL, SocketConfig{Filter: nil, Promiscuous: true})
	if err != nil {
		fmt.Printf("conn error: %s", err)
		return nil, err
	}
	return Config{Conn: conn, NICInfo: nicinfo, OfflineDeadline: DefaultOfflineDeadline, PurgeDeadline: DefaultPurgeDeadline}.NewSession()
}

func (config Config) NewSession() (*Session, error) {
	session := new(Session)
	session.MACTable = newMACTable()
	session.HostTable = newHostTable()
	session.Statisticsts = make([]ProtoStats, 32)
	session.NICInfo = &NICInfo{HostAddr4: Addr{MAC: EthBroadcast, IP: IP4Broadcast}}
	session.C = make(chan Notification, 128) // plenty of capacity to prevent blocking
	session.Conn = config.Conn
	session.NICInfo = config.NICInfo
	if session.OfflineDeadline = config.OfflineDeadline; session.OfflineDeadline < 0 || session.OfflineDeadline > time.Hour*24 {
		session.OfflineDeadline = DefaultOfflineDeadline
	}
	if session.PurgeDeadline = config.PurgeDeadline; session.PurgeDeadline < 0 || session.PurgeDeadline > time.Hour*24 {
		session.PurgeDeadline = DefaultPurgeDeadline
	}

	// TODO: fix this to discard writes like ioutil.Discard
	// session.Conn, _ = net.ListenPacket("udp4", "127.0.0.1:0")

	// Setup a nic monitoring goroutine to ensure we always receive IP packets.
	// If the switch port is disabled or the the nic stops receiving packets for any reason,
	// our best option is to stop the engine and likely restart.
	//
	go func() {
		ticker := time.NewTicker(monitorNICFrequency)
		for {
			select {
			case <-ticker.C:
				if atomic.LoadUint32(&session.ipHeartBeat) == 0 {
					fmt.Printf("fatal: failed to receive ip packets in duration=%s - sending sigterm time=%v\n", monitorNICFrequency, time.Now())
					// Send sigterm to terminate process
					syscall.Kill(os.Getpid(), syscall.SIGTERM)
				}
				atomic.StoreUint32(&session.ipHeartBeat, 0)
			case <-session.closeChan:
				return
			}
		}
	}()

	return session, nil
}

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
/*
func (h *Session) NewPacketConn(ifi *net.Interface, proto uint16, cfg SocketConfig) (err error) {
	h.Conn, err = NewServerConn(ifi, proto, cfg)

	return err
}
*/

func (h *Session) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := h.Conn.ReadFrom(b)
		if err == nil {
			return n, addr, err
		}

		if err, ok := err.(net.Error); ok && err.Temporary() {
			fmt.Println("tmp conn read error", err)
			continue
		}
		return n, addr, err
	}
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

func (h *Session) minuteLoop() {
	ticker := time.NewTicker(time.Minute)
	counter := 60
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			counter--
			go h.purge(now)

		case <-h.closeChan:
			fmt.Println("engine: minute loop goroutine ended")
			return
		}
	}
}

// purge set entries offline and subsequently delete them if no more traffic received.
// The funcion is called each minute by the minute goroutine.
func (h *Session) purge(now time.Time) error {
	offlineCutoff := now.Add(h.OfflineDeadline * -1) // Mark offline entries last updated before this time
	deleteCutoff := now.Add(h.PurgeDeadline * -1)    // Delete entries that have not responded in last hour

	purge := make([]net.IP, 0, 16)
	offline := make([]*Host, 0, 16)

	// h.session.GlobalRLock()
	table := h.GetHosts()
	for _, e := range table {
		e.MACEntry.Row.RLock()

		// Delete from table if the device is offline and was not seen for the last hour
		if !e.Online && e.LastSeen.Before(deleteCutoff) {
			purge = append(purge, e.Addr.IP)
			e.MACEntry.Row.RUnlock()
			continue
		}

		// Set offline if no updates since the offline deadline
		if e.Online && e.LastSeen.Before(offlineCutoff) {
			offline = append(offline, e)
		}
		e.MACEntry.Row.RUnlock()
	}

	for _, host := range offline {
		h.SetOffline(host) // will lock/unlock row
	}

	// delete after loop because this will change the table
	if len(purge) > 0 {
		for _, v := range purge {
			h.DeleteHost(v)
		}
	}
	return nil
}
