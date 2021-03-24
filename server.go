package packet

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"
)

// Debug packets turn on logging if desirable
var (
	Debug    bool
	DebugIP6 bool
	DebugIP4 bool
	DebugUDP bool
)

// Config has a list of configurable parameters that overide package defaults
type Config struct {
	// Conn enables the client to override the connection with a another packet conn
	// useful for testing
	Conn                    net.PacketConn // listen connectinon
	NICInfo                 *NICInfo       // override nic information
	FullNetworkScanInterval time.Duration  // Set it to zero if no scan required
	ProbeInterval           time.Duration  // how often to probe if IP is online
	OfflineDeadline         time.Duration  // mark offline if more than OfflineInte
	PurgeDeadline           time.Duration
}

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler struct {
	NICInfo      *NICInfo
	conn         net.PacketConn
	LANHosts     HostTable // store IP list - one for each host
	MACTable     MACTable  // store mac list
	HandlerIP4   PacketProcessor
	HandlerIP6   PacketProcessor
	HandlerICMP4 PacketProcessor
	HandlerICMP6 PacketProcessor
	HandlerDHCP4 PacketProcessor
	HandlerARP   PacketProcessor
	// callback                []func(Notification) error
	FullNetworkScanInterval time.Duration // Set it to -1 if no scan required
	ProbeInterval           time.Duration // how often to probe if IP is online
	OfflineDeadline         time.Duration // mark offline if no updates
	PurgeDeadline           time.Duration // purge entry if no updates
	closed                  bool          // set to true when handler is closed
	closeChan               chan bool     // close goroutines channel
	mutex                   sync.RWMutex
	nameChannel             chan Notification
}

func (h *Handler) GetNotificationChannel() <-chan Notification {
	if h.nameChannel != nil {
		return h.nameChannel
	}

	// Notify of all existing hosts
	list := []Notification{}
	h.mutex.RLock()
	for _, host := range h.LANHosts.Table {
		host.Row.RLock()
		if host.dhcp4Store.Name != "" {
			list = append(list, Notification{Addr: Addr{IP: host.IP, MAC: host.MACEntry.MAC}, Online: host.Online, DHCPName: host.dhcp4Store.Name})
		}
		host.Row.RUnlock()
	}
	h.mutex.RUnlock()

	h.nameChannel = make(chan Notification, notificationChannelCap)

	go func() {
		for _, n := range list {
			h.nameChannel <- n
			time.Sleep(time.Millisecond * 5) // time for reader to process
		}
	}()

	return h.nameChannel
}

// PacketNOOP is a no op packet processor
type PacketNOOP struct{}

var _ PacketProcessor = PacketNOOP{}

func (p PacketNOOP) Start() error                               { return nil }
func (p PacketNOOP) Stop() error                                { return nil }
func (p PacketNOOP) ProcessPacket(*Host, []byte) (*Host, error) { return nil, nil }
func (p PacketNOOP) StartHunt(addr Addr) (HuntStage, error)     { return StageNoChange, nil }
func (p PacketNOOP) StopHunt(addr Addr) (HuntStage, error)      { return StageNoChange, nil }

// func (p PacketNOOP) HuntStage(addr Addr) HuntStage              { return StageNormal }
func (p PacketNOOP) MinuteTicker(now time.Time) error { return nil }

// New creates an ICMPv6 handler with default values
func NewEngine(nic string) (*Handler, error) {
	return Config{}.NewEngine(nic)
}

const notificationChannelCap = 16

// NewEngine creates an packet handler with config values
func (config Config) NewEngine(nic string) (*Handler, error) {

	var err error

	h := &Handler{LANHosts: newHostTable(), closeChan: make(chan bool)}
	h.MACTable = newMACTable(h)

	h.NICInfo = config.NICInfo
	if h.NICInfo == nil {
		h.NICInfo, err = GetNICInfo(nic)
		if err != nil {
			return nil, fmt.Errorf("interface not found nic=%s: %w", nic, err)
		}
	}

	h.FullNetworkScanInterval = config.FullNetworkScanInterval
	if h.FullNetworkScanInterval != -1 && (h.FullNetworkScanInterval <= 0 || h.FullNetworkScanInterval > time.Hour*12) {
		h.FullNetworkScanInterval = time.Minute * 60
	}
	h.ProbeInterval = config.ProbeInterval
	if h.ProbeInterval <= 0 || h.ProbeInterval > time.Minute*10 {
		h.ProbeInterval = time.Minute * 2
	}
	h.OfflineDeadline = config.OfflineDeadline
	if h.OfflineDeadline <= h.ProbeInterval {
		h.OfflineDeadline = h.ProbeInterval * 2
	}
	h.PurgeDeadline = config.PurgeDeadline
	if h.PurgeDeadline <= h.OfflineDeadline {
		h.PurgeDeadline = time.Minute * 61
	}

	// Skip if conn is overriden
	h.conn = config.Conn
	if h.conn == nil {
		h.conn, err = h.setupConn()
		if err != nil {
			return nil, err
		}
	}

	// no plugins to start
	h.HandlerARP = PacketNOOP{}
	h.HandlerIP4 = PacketNOOP{}
	h.HandlerIP6 = PacketNOOP{}
	h.HandlerARP = PacketNOOP{}
	h.HandlerICMP4 = PacketNOOP{}
	h.HandlerICMP6 = PacketNOOP{}
	h.HandlerDHCP4 = PacketNOOP{}

	// create the host entry manually because we don't process host packets
	host, _ := h.findOrCreateHost(h.NICInfo.HostMAC, h.NICInfo.HostIP4.IP)
	host.LastSeen = time.Now().Add(time.Hour * 24 * 365) // never expire
	host.Online = true

	return h, nil
}

// Close closes the underlying sockets
func (h *Handler) Close() error {
	if Debug {
		fmt.Println("packet: close() called. closing....")
	}
	h.closed = true
	if h.nameChannel != nil {
		close(h.nameChannel)
	}
	close(h.closeChan) // will terminate goroutines
	h.conn.Close()
	return nil
}

// Conn return the underlying raw socket conn
func (h *Handler) Conn() net.PacketConn {
	return h.conn
}

func (h *Handler) setupConn() (conn net.PacketConn, err error) {

	// see syscall constants for full list of available network protocols
	// https://golang.org/pkg/syscall/
	//
	// For a list of bpf instructions
	// https://tshark.dev/packetcraft/arcana/bpf_instructions/
	//
	// TODO: Set direction - aparently this only works on bsd
	// https://github.com/google/gopacket/blob/master/pcap/pcap.go
	// https://github.com/mdlayher/raw/blob/master/raw.go
	//
	// TODO: use zero copy in bpf
	// https://www.gsp.com/cgi-bin/man.cgi?topic=BPF
	bpf, err := bpf.Assemble([]bpf.Instruction{
		// Check EtherType
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 80221Q? Virtual LAN over 802.3 Ethernet
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_8021Q, SkipFalse: 1}, // EtherType is 2 pushed out by two bytes
		bpf.LoadAbsolute{Off: 14, Size: 2},
		// IPv4?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_IP, SkipFalse: 1},
		bpf.RetConstant{Val: EthMaxSize},
		// IPv6?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_IPV6, SkipFalse: 1},
		bpf.RetConstant{Val: EthMaxSize},
		// ARP?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_ARP, SkipFalse: 1},
		bpf.RetConstant{Val: EthMaxSize},
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		log.Fatal("bpf assemble error", err)
	}

	// see: https://www.man7.org/linux/man-pages/man7/packet.7.html
	conn, err = NewServerConn(h.NICInfo.IFI, syscall.ETH_P_ALL, SocketConfig{Filter: bpf})
	if err != nil {
		return nil, fmt.Errorf("packet.ListenPacket error: %w", err)
	}

	// don't timeout during write
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return conn, nil
}

// PrintTable logs the table to standard out
func (h *Handler) PrintTable() {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	fmt.Printf("mac table len=%d\n", len(h.MACTable.Table))
	h.printMACTable()
	fmt.Printf("hosts table len=%v\n", len(h.LANHosts.Table))
	h.printHostTable()
}

// isUnicastMAC return true if the mac address is unicast
//
// Bit 0 in the first octet is reserved for broadcast or multicast traffic.
// When we have unicast traffic this bit will be set to 0.
// For broadcast or multicast traffic this bit will be set to 1.
func isUnicastMAC(mac net.HardwareAddr) bool {
	if mac[0]&0x01 == 0x00 {
		return true
	}
	return false
}

func (h *Handler) startPlugins() error {
	time.Sleep(time.Millisecond * 200) // wait for read to start

	if err := h.HandlerIP4.Start(); err != nil {
		fmt.Println("error: in IP4 start:", err)
	}
	if err := h.HandlerIP6.Start(); err != nil {
		fmt.Println("error: in IP6 start:", err)
	}
	if err := h.HandlerICMP4.Start(); err != nil {
		fmt.Println("error: in ICMP4 start:", err)
	}
	if err := h.HandlerICMP6.Start(); err != nil {
		fmt.Println("error: in ICMP6 start:", err)
	}
	if err := h.HandlerARP.Start(); err != nil {
		fmt.Println("error: in ARP start:", err)
	}
	if err := h.HandlerDHCP4.Start(); err != nil {
		fmt.Println("error: in DHCP4 start:", err)
	}
	return nil
}

func (h *Handler) stopPlugins() error {
	if err := h.HandlerIP4.Stop(); err != nil {
		fmt.Println("error: in IP4 stop:", err)
	}
	if err := h.HandlerIP6.Stop(); err != nil {
		fmt.Println("error: in IP6 stop:", err)
	}
	if err := h.HandlerICMP4.Stop(); err != nil {
		fmt.Println("error: in ICMP4 stop:", err)
	}
	if err := h.HandlerICMP6.Stop(); err != nil {
		fmt.Println("error: in ICMP6 stop:", err)
	}
	if err := h.HandlerARP.Stop(); err != nil {
		fmt.Println("error: in ARP stop:", err)
	}
	if err := h.HandlerDHCP4.Stop(); err != nil {
		fmt.Println("error: in DHCP4 stop:", err)
	}
	return nil
}

func (h *Handler) minuteLoop() {
	ticker := time.Tick(time.Minute)
	for {
		select {
		case <-ticker:
			h.minuteChecker(time.Now())

		case <-h.closeChan:
			return
		}
	}
}

func (h *Handler) minuteChecker(now time.Time) {
	if Debug {
		fmt.Printf("packet: running minute checker %v\n", now)
	}

	// Handlers
	h.HandlerARP.MinuteTicker(now)
	h.HandlerICMP4.MinuteTicker(now)
	h.HandlerICMP6.MinuteTicker(now)
	h.HandlerDHCP4.MinuteTicker(now)

	// internal checks
	h.purge(now, h.OfflineDeadline, h.PurgeDeadline)
	h.routeMonitor(now)

}

// ListenAndServe listen for raw packets and invoke hooks as required
func (h *Handler) ListenAndServe(ctxt context.Context) (err error) {

	// start all plugins
	go h.startPlugins()
	defer h.stopPlugins()

	go h.minuteLoop()

	var d1, d2, d3 time.Duration
	var startTime time.Time
	buf := make([]byte, EthMaxSize)
	for {
		if err = h.conn.SetReadDeadline(time.Now().Add(time.Second * 2)); err != nil {
			if h.closed { // closed by call to h.Close()?
				return nil
			}
			return fmt.Errorf("setReadDeadline error: %w", err)
		}

		n, _, err := h.conn.ReadFrom(buf)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			if h.closed { // closed by call to h.Close()?
				return nil
			}
			return fmt.Errorf("read error: %w", err)
		}
		startTime = time.Now()

		ether := Ether(buf[:n])
		if !ether.IsValid() {
			log.Error("icmp invalid ethernet packet ", ether.EtherType())
			continue
		}

		// Ignore packets sent via our interface
		// If we don't have this, then we received all forward packets with client IPs but our mac
		//
		// TODO: should this be in the bpf rules?
		if bytes.Equal(ether.Src(), h.NICInfo.HostMAC) {
			continue
		}
		// fmt.Println("DEBUG ether ", ether)

		// Only interested in unicast ethernet
		if !isUnicastMAC(ether.Src()) {
			continue
		}

		notify := false
		var ip4Frame IP4
		var ip6Frame IP6
		var l4Proto int
		var l4Payload []byte
		var host *Host
		switch ether.EtherType() {
		case syscall.ETH_P_IP: // 0x0800
			ip4Frame = IP4(ether.Payload())
			if !ip4Frame.IsValid() {
				fmt.Println("packet: error invalid ip4 frame type=", ether.EtherType())
				continue
			}
			if DebugIP4 {
				fmt.Println("ether:", ether)
				fmt.Println("ip4  :", ip4Frame)
			}

			// Only lookup host on same subnet
			// Note: DHCP request for previous discover have zero src IP; therefore wont't create host entry here.
			if h.NICInfo.HostIP4.Contains(ip4Frame.Src()) {
				host, _ = h.FindOrCreateHost(ether.Src(), ip4Frame.Src()) // will lock/unlock
			}
			l4Proto = ip4Frame.Protocol()
			l4Payload = ip4Frame.Payload()

		case syscall.ETH_P_IPV6: // 0x86dd
			ip6Frame = IP6(ether.Payload())
			if !ip6Frame.IsValid() {
				fmt.Println("packet: error invalid ip6 frame type=", ether.EtherType())
				continue
			}
			if DebugIP6 {
				fmt.Printf("ether: %s\n", ether)
				fmt.Printf("ip6  : %s\n", ip6Frame)
			}

			l4Proto = ip6Frame.NextHeader()
			l4Payload = ip6Frame.Payload()

			// lookup host only if unicast
			if ip6Frame.Src().IsLinkLocalUnicast() || ip6Frame.Src().IsGlobalUnicast() {
				host, _ = h.FindOrCreateHost(ether.Src(), ip6Frame.Src()) // will lock/unlock
			}

		case syscall.ETH_P_ARP: // 0x806
			l4Proto = syscall.ETH_P_ARP // treat arp as l4 proto; similar to IP6 ICMP NDP

		default:
			fmt.Printf("packet: error invalid ethernet type=%x\n", ether.EtherType())
			continue
		}
		d1 = time.Since(startTime)

		switch l4Proto {
		case syscall.IPPROTO_ICMP:
			if host, err = h.HandlerICMP4.ProcessPacket(host, l4Payload); err != nil {
				fmt.Printf("packet: error processing icmp4: %s\n", err)
			}
		case syscall.IPPROTO_ICMPV6: // 0x03a
			if host, err = h.HandlerICMP6.ProcessPacket(host, ether); err != nil {
				fmt.Printf("packet: error processing icmp6: %s\n", err)
			}
		case syscall.IPPROTO_IGMP:
			// Internet Group Management Protocol - Ipv4 multicast groups
			// do nothing
		case syscall.IPPROTO_TCP:
			// skip tcp
		case syscall.IPPROTO_UDP:
			udp := UDP(l4Payload)
			if !udp.IsValid() {
				fmt.Println("packet: error invalid udp frame ", ip4Frame)
				continue
			}
			if ip4Frame != nil {
				if DebugUDP {
					fmt.Println("ether:", ether)
					fmt.Println("ip4  :", ip4Frame)
					fmt.Printf("udp  : %s\n", udp)
				}

				// DHCP4 packet?
				if udp.DstPort() == DHCP4ServerPort || udp.DstPort() == DHCP4ClientPort {
					name := ""
					if host != nil {
						name = host.dhcp4Store.Name
					}
					if host, err = h.HandlerDHCP4.ProcessPacket(host, ether); err != nil {
						fmt.Printf("packet: error processing dhcp4: %s\n", err)
					}
					if host != nil && host.dhcp4Store.Name != name {
						notify = true
					}
				}
			} else {
				if DebugUDP {
					fmt.Println("ether:", ether)
					fmt.Println("ip6  :", ip6Frame)
					fmt.Printf("udp  : %s\n", udp)
				}

			}

		case syscall.ETH_P_ARP: // skip ARP - 0x0806
			if host, err = h.HandlerARP.ProcessPacket(host, ether); err != nil {
				fmt.Printf("packet: error processing arp: %s\n", err)
			}

		default:
			fmt.Println("packet: unsupported level 4 header", l4Proto, ether)
		}
		d2 = time.Since(startTime)

		if host != nil {
			h.lockAndSetOnline(host, notify)
		}

		d3 = time.Since(startTime)
		if d3 > time.Microsecond*100 {
			fmt.Printf("packet: warning > 100 microseconds: etherType=%x l4proto=%x l3=%v l4=%v total=%v\n", ether.EtherType(), l4Proto, d1, d2, d3)
		}

		/****
		 ** Uncomment this to help identify deadlocks
		 **
		if Debug {
			fmt.Println("Check engine")
			h.mutex.Lock()
			fmt.Println("Check lock engine pass")
			for _, host := range h.LANHosts.Table {
				fmt.Println("Check row ", host.IP)
				host.Row.Lock()
				fmt.Println("Check lock row pass ", host.IP)
				host.Row.Unlock()
				fmt.Println("Check unlock row pass ", host.IP)
			}
			fmt.Println("Check lock pass rows")
			h.mutex.Unlock()
			fmt.Println("Check unlock engine pass ")
		}
		 **/
	}
}

// lockAndSetOnline will ensure this host is marked as online and that an
// event is generated if host is transitioning to online
//
// This funcion will also mark the previous IP4 host as offline
//  Parameters:
//     notify: force a notification as another parameter (likely name) has changed
func (h *Handler) lockAndSetOnline(host *Host, notify bool) {
	now := time.Now()

	host.Row.RLock()

	if host.Online && !notify { // just another IP packet - nothing to do
		if now.Sub(host.LastSeen) < time.Second*1 { // update LastSeen every 1 seconds to minimise locking
			host.Row.RUnlock()
			return
		}
	}

	// if transitioning to online, test if we need to make previous IP offline
	var offlineIP net.IP
	if !host.Online {
		if host.IP.To4() != nil {
			if !host.IP.Equal(host.MACEntry.IP4) { // changed IP4
				fmt.Printf("packet: host changed ip4 from=%s to=%s\n", host.MACEntry.IP4, host.IP)
				offlineIP = host.MACEntry.IP4 // last IP
			}
		} else {
			if host.IP.IsGlobalUnicast() && !host.IP.Equal(host.MACEntry.IP6GUA) { // changed IP6 global unique address
				fmt.Printf("packet: host changed ip6 from=%s to=%s\n", host.MACEntry.IP6GUA, host.IP)
				offlineIP = host.MACEntry.IP6GUA
			}
			if host.IP.IsLinkLocalUnicast() && !host.IP.Equal(host.MACEntry.IP6LLA) { // changed IP6 link local address
				fmt.Printf("packet: host changed ip6LLA from=%s to=%s\n", host.MACEntry.IP6LLA, host.IP)
				// don't set offline IP as we don't target LLA
			}
		}
	}
	host.Row.RUnlock()

	// set previous IP to offline, start hunt and notify of new IP
	if offlineIP != nil {
		previousHost := h.FindIP(offlineIP) // will lock the engine; we cannot have Row lock
		if previousHost != nil {
			h.lockAndSetOffline(previousHost)
		}
	}

	// lock row for update
	host.Row.Lock()
	defer host.Row.Unlock()

	// update LastSeen and current mac IP
	host.MACEntry.LastSeen = now
	host.LastSeen = now
	host.MACEntry.updateIP(host.IP)

	// return immediately if host already online and not notification
	if host.Online && !notify {
		return
	}

	// if mac is captured, then start hunting process when IP is online
	captured := host.MACEntry.Captured

	host.MACEntry.Online = true
	host.Online = true
	addr := Addr{IP: host.IP, MAC: host.MACEntry.MAC}
	notification := Notification{Addr: addr, Online: true, DHCPName: host.dhcp4Store.Name}

	if Debug {
		fmt.Printf("packet: IP is online %s\n", host)
	}

	// in goroutine - cannot access host fields
	go func() {
		if captured {
			if err := h.lockAndStartHunt(addr); err != nil {
				fmt.Println("packet: failed to start hunt error", err)
			}
		}
		if h.nameChannel != nil {
			h.nameChannel <- notification
		}
	}()
}

func (h *Handler) lockAndSetOffline(host *Host) {
	host.Row.Lock()
	if !host.Online {
		return
	}
	if Debug {
		fmt.Printf("packet: IP is offline %s\n", host)
	}
	host.Online = false
	notification := Notification{Addr: Addr{MAC: host.MACEntry.MAC, IP: host.IP}, Online: false}
	host.Row.Unlock()

	h.lockAndStopHunt(host)

	go func() {
		if h.nameChannel != nil {
			h.nameChannel <- notification
		}
	}()
}
