package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/irai/packet/fastlog"
)

const module = "packet"

// Global variables
var (
	Logger = fastlog.New(module)

	IPv4bcast = netip.MustParseAddr("255.255.255.255") // limited broadcast
	IPv4zero  = netip.MustParseAddr("0.0.0.0")
	IPv6zero  = netip.MustParseAddr("::")

	IP4Broadcast     = netip.MustParseAddr("255.255.255.255")
	IP4BroadcastAddr = Addr{MAC: EthBroadcast, IP: IP4Broadcast}

	EthBroadcast          = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	IP4AllNodesMulticast  = netip.MustParseAddr("224.0.0.1")
	Eth4AllNodesMulticast = net.HardwareAddr{0x01, 0x00, 0x5e, 0, 0, 0x01} // Ethernet multicast 01-00-5E plus low-order 23-bits of the IP address.
	IP4AllNodesAddr       = Addr{MAC: Eth4AllNodesMulticast, IP: IP4AllNodesMulticast}

	IP4AllRoutersMulticast = netip.MustParseAddr("224.0.0.2")
	Eth4RoutersMulticast   = net.HardwareAddr{0x01, 0x00, 0x5e, 0, 0, 0x02}

	Eth6AllNodesMulticast = net.HardwareAddr{0x33, 0x33, 0, 0, 0, 0x01}
	IP6AllNodesMulticast  = netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})
	IP6AllNodesAddr       = Addr{MAC: Eth6AllNodesMulticast, IP: IP6AllNodesMulticast}

	Eth6AllRoutersMulticast = net.HardwareAddr{0x33, 0x33, 0, 0, 0, 0x02}
	IP6AllRoutersMulticast  = netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})
	IP6AllRoutersAddr       = Addr{MAC: Eth6AllRoutersMulticast, IP: IP6AllRoutersMulticast}

	IP6DefaultRouter = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})
)

// Sentinel errors
var (
	ErrInvalidLen    = errors.New("invalid len")
	ErrPayloadTooBig = errors.New("payload too big")
	ErrParseFrame    = errors.New("failed to parse frame")
	ErrParseProtocol = errors.New("invalid protocol")
	ErrFrameLen      = errors.New("invalid frame length")
	ErrInvalidConn   = errors.New("invalid connection")
	ErrInvalidIP     = errors.New("invalid ip")
	ErrInvalidMAC    = errors.New("invalid mac")
	ErrInvalidIP6LLA = errors.New("invalid ip6 lla")
	ErrNotFound      = errors.New("not found")
	ErrTimeout       = errors.New("timeout")
	ErrNotRedirected = errors.New("not redirected")
	ErrIsRouter      = errors.New("host is router")
	ErrNoReader      = errors.New("no reader")
	ErrInvalidParam  = errors.New("invalid parameter")
	ErrMulticastMAC  = errors.New("mac is multicast")
	ErrHandlerClosed = errors.New("handler is closed")
)

// CLoudFlare family
// https://developers.cloudflare.com/1.1.1.1/1.1.1.1-for-families
var (
	DNSv4CloudFlare1       = netip.MustParseAddr("1.1.1.2") // malware
	DNSv6Cloudflare1       = netip.AddrFrom16([16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11})
	DNSv4CloudFlare2       = netip.MustParseAddr("1.0.0.2") // malware
	DNSv6Cloudflare2       = netip.AddrFrom16([16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x01})
	DNSv4CloudFlareFamily1 = netip.MustParseAddr("1.1.1.3") // malware and adult sites
	DNSv4CloudFlareFamily2 = netip.MustParseAddr("1.0.0.3") // malware and adult sites

	// OpenDNS
	OpenDNS1 = netip.MustParseAddr("208.67.222.123")
	OpenDNS2 = netip.MustParseAddr("208.67.220.123")
)

// Session holds the session context for a given network interface.
type Session struct {
	Conn            net.PacketConn    // the underlaying raw connection used for all read and write
	NICInfo         *NICInfo          // keep interface information
	ProbeDeadline   time.Duration     // send IP probe if no traffic received for this long
	OfflineDeadline time.Duration     // mark Host offline if no traffic for this long
	PurgeDeadline   time.Duration     // delete Host if no traffic for this long
	HostTable       HostTable         // store MAC/IP list - one for each IP host
	MACTable        MACTable          // store mac list
	mutex           sync.RWMutex      // global session mutex
	Statistics      []ProtoStats      // keep per protocol statistics
	C               chan Notification // channel for online & offline notifications
	closeChan       chan bool         // channel to end all go routines
	closed          bool              // indicate the session is closed
	ipHeartBeat     uint32            // ipHeartBeat is set to 1 when we receive an IP packet
}

// Config contains configurable parameters that overide package defaults
type Config struct {
	Conn            net.PacketConn // override underlying connection - useful for testing
	NICInfo         *NICInfo       // override nic information - set to non nil to create a test Handler
	ProbeDeadline   time.Duration  // override probe deadline
	OfflineDeadline time.Duration  // override offline deadline
	PurgeDeadline   time.Duration  // override purge deadline
}

// Default dealines
const (
	DefaultProbeDeadline   = time.Minute * 2  // probe IP every two minutes
	DefaultOfflineDeadline = time.Minute * 5  // set offline if not IP not seen for this long
	DefaultPurgeDeadline   = time.Minute * 61 // purge from table if not seen for this long
)

// monitorNICFrequency sets the frequency to check the network card is working properly.
// It is a variable so we can test easily.
var monitorNICFrequency = time.Minute * 3

// NewSession returns a session to read and write raw packets from the network interface card.
func NewSession(nic string) (*Session, error) {
	return Config{ProbeDeadline: DefaultProbeDeadline, OfflineDeadline: DefaultOfflineDeadline, PurgeDeadline: DefaultPurgeDeadline}.NewSession(nic)
}

// NewSession accepts a configuration structure and returns a session to read and write raw packets from the network interface card.
func (config Config) NewSession(nic string) (session *Session, err error) {
	session = new(Session)
	session.MACTable = newMACTable()
	session.HostTable = newHostTable()
	session.C = make(chan Notification, 128) // plenty of capacity to prevent blocking
	session.closeChan = make(chan bool)

	if session.NICInfo = config.NICInfo; session.NICInfo == nil {
		session.NICInfo, err = GetNICInfo(nic)
		if err != nil {
			return nil, fmt.Errorf("failed to setup nic=%s: %w", nic, err)
		}
	}
	if session.Conn = config.Conn; session.Conn == nil {
		session.Conn, err = NewServerConn(session.NICInfo.IFI, syscall.ETH_P_ALL, SocketConfig{Filter: nil, Promiscuous: true})
		if err != nil {
			return nil, fmt.Errorf("failed to open raw connection: %w", err)
		}

	}

	// create and populate stats table
	session.Statistics = make([]ProtoStats, 32)
	for i := 1; i < len(session.Statistics); i++ {
		session.Statistics[i].Proto = PayloadID(i)
	}

	if config.ProbeDeadline == 0 || config.OfflineDeadline == 0 || config.PurgeDeadline == 0 {
		config.ProbeDeadline = DefaultProbeDeadline
		config.OfflineDeadline = DefaultOfflineDeadline
		config.PurgeDeadline = DefaultPurgeDeadline
	}

	if session.ProbeDeadline = config.ProbeDeadline; session.ProbeDeadline <= 0 || session.ProbeDeadline > time.Minute*30 {
		return nil, fmt.Errorf("invalid ProbeDeadline=%v: %w", session.ProbeDeadline, ErrInvalidParam)
	}
	if session.OfflineDeadline = config.OfflineDeadline; session.OfflineDeadline <= 0 || session.OfflineDeadline > time.Minute*60 || session.OfflineDeadline < session.ProbeDeadline {
		return nil, fmt.Errorf("invalid OfflineDeadline=%v: %w", session.OfflineDeadline, ErrInvalidParam)
	}
	if session.PurgeDeadline = config.PurgeDeadline; session.PurgeDeadline <= 0 || session.PurgeDeadline > time.Hour*24 {
		return nil, fmt.Errorf("invalid PurgeDeadline=%v: %w", session.PurgeDeadline, ErrInvalidParam)
	}

	// Setup a goroutine to monitor the nic to ensure we receive IP packets frequently.
	// If the nic stops receiving IP packets, it is likely the switch port is disabled
	// and our best option is to stop and likely restart.
	go func(h *Session) {
		ticker := time.NewTicker(monitorNICFrequency)
		for {
			select {
			case <-ticker.C:
				if atomic.LoadUint32(&h.ipHeartBeat) == 0 {
					Logger.Msg("fatal failure to receive ip packets").Duration("duration", monitorNICFrequency).Time("time", time.Now()).Write()
					// Send sigterm to terminate process
					syscall.Kill(os.Getpid(), syscall.SIGTERM)
				}
				atomic.StoreUint32(&h.ipHeartBeat, 0)
			case <-session.closeChan:
				if Logger.IsDebug() {
					Logger.Msg("nic monitoring goroutine ended").Write()
				}
				return
			}
		}
	}(session)

	// Start a minute loop goroutine to check for offline transition
	go func(h *Session) {
		ticker := time.NewTicker(time.Minute)
		for {
			select {
			case <-ticker.C:
				if Logger.IsDebug() {
					Logger.Msg("minute check").Write()
				}
				go h.purge(time.Now())

			case <-h.closeChan:
				Logger.Msg("session minute loop goroutine ended").Write()
				return
			}
		}
	}(session)

	// create our own Host entry manually because we don't create for host packets
	host, _ := session.findOrCreateHostWithLock(session.NICInfo.HostAddr4)
	host.LastSeen = time.Now().Add(time.Hour * 24 * 365) // never expire
	host.MACEntry.LastSeen = host.LastSeen
	host.MACEntry.IP4 = host.Addr.IP
	host.MACEntry.IP6LLA = session.NICInfo.HostLLA.Addr()
	host.Online = true
	host.MACEntry.Online = true

	// create the router entry manually and set router flag
	host, _ = session.findOrCreateHostWithLock(session.NICInfo.RouterAddr4)
	host.MACEntry.IsRouter = true
	host.MACEntry.IP4 = host.Addr.IP
	host.Online = true
	host.MACEntry.Online = true

	return session, nil
}

// Close stop all session goroutines and close notification channel and the underlaying raw connection.
// The session is no longer valid after calling Close().
func (h *Session) Close() {
	if h.closed {
		return
	}
	h.closed = true
	close(h.closeChan)
	close(h.C)
	h.Conn.Close()
	time.Sleep(time.Second) // give time for goroutines to end
}

func (h *Session) EnableIP4Forwarding() error {
	return EnableIP4Forwarding(h.NICInfo.IFI.Name)
}

// PrintTable logs the table to standard out.
func (h *Session) PrintTable() {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	fmt.Printf("mac table len=%d\n", len(h.MACTable.Table))
	h.printMACTable()
	fmt.Printf("hosts table len=%v\n", len(h.HostTable.Table))
	h.printHostTable()
}

func (h *Session) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := h.Conn.ReadFrom(b)
		if err == nil {
			return n, addr, err
		}

		if err, ok := err.(net.Error); ok && err.Temporary() {
			if Logger.IsDebug() {
				Logger.Msg("temporary conn read error").Error(err).Write()
			}
			continue
		}
		if h.closed {
			return n, addr, ErrHandlerClosed
		}
		return n, addr, err
	}
}

// purge set entries offline and subsequently delete them if no more traffic received.
// The funcion is called each minute by the minute goroutine.
// now is a parameter to allow testing - i.e set a now to future to trigger events quickly.
func (h *Session) purge(now time.Time) error {
	probeCutoff := now.Add(h.ProbeDeadline * -1)     // Check entries last updated before this time
	offlineCutoff := now.Add(h.OfflineDeadline * -1) // Mark offline entries last updated before this time
	deleteCutoff := now.Add(h.PurgeDeadline * -1)    // Delete entries that have not responded in last hour

	purge := make([]netip.Addr, 0, 16)
	probe := make([]Addr, 0, 16)
	offline := make([]*Host, 0, 16)

	table := h.GetHosts()
	for _, e := range table {
		e.MACEntry.Row.RLock()

		// Delete from table if the device is offline and was not seen for the last hour
		if !e.Online && e.LastSeen.Before(deleteCutoff) {
			purge = append(purge, e.Addr.IP)
			e.MACEntry.Row.RUnlock()
			continue
		}

		// Probe if device not seen recently
		if e.Online && e.LastSeen.Before(probeCutoff) {
			probe = append(probe, e.Addr)
		}

		// Set offline if no updates since the offline deadline
		if e.Online && e.LastSeen.Before(offlineCutoff) {
			offline = append(offline, e)
		}
		e.MACEntry.Row.RUnlock()
	}

	// run probe addr in goroutine as it may take time to return
	if len(probe) > 0 {
		go func() {
			for _, addr := range probe {
				if addr.IP.Is4() {
					if Logger.IsDebug() {
						Logger.Msg("send arp request - who is").IP("ip", addr.IP).Write()
					}
					if err := h.arpRequest(EthernetBroadcast, h.NICInfo.HostAddr4, Addr{MAC: EthernetBroadcast, IP: addr.IP}); err != nil {
						Logger.Msg("failed to probe ipv4").IP("ip", addr.IP).Error(err).Write()
					}
				} else {
					if !h.NICInfo.HostLLA.Addr().Is6() { // in case host does not have IPv6 - this should never happen
						Logger.Msg("failed to probe ipv6 missing host ipv6").IP("ip", h.NICInfo.HostLLA.Addr()).Write()
						continue
					}
					srcAddr := Addr{MAC: h.NICInfo.HostAddr4.MAC, IP: h.NICInfo.HostLLA.Addr()}
					if addr.IP.IsLinkLocalUnicast() {
						// Use Neigbour solicitation if link local address as NS almost always result in a response from host if online unless
						// host is on battery saving mode.
						if err := h.ICMP6SendNeighbourSolicitation(srcAddr, IPv6SolicitedNode(addr.IP), addr.IP); err != nil {
							Logger.Msg("failed to probe ipv6 LLA").IP("ip", addr.IP).Error(err).Write()
						}
						return
					}
					if err := h.ICMP6SendEchoRequest(srcAddr, addr, uint16(now.Nanosecond()), 0); err != nil {
						Logger.Msg("failed to probe ipv6").IP("ip", addr.IP).Error(err).Write()
					}
				}
			}
		}()
	}

	for _, host := range offline {
		h.makeOffline(host) // will lock/unlock row
	}

	// delete after loop because this will change the table
	if len(purge) > 0 {
		h.mutex.Lock()
		for _, v := range purge {
			h.deleteHost(v)
		}
		h.mutex.Unlock()
	}
	return nil
}

// arpRequest is an internal funcion to send an ARP request packet
func (h *Session) arpRequest(dst net.HardwareAddr, sender Addr, target Addr) (err error) {
	b := EtherBufferPool.Get().(*[EthMaxSize]byte)
	defer EtherBufferPool.Put(b)
	ether := Ether(b[0 : EthHeaderLen+28])                                      // arp length - 28 bytes
	ether = EncodeEther(ether, syscall.ETH_P_ARP, h.NICInfo.HostAddr4.MAC, dst) // ether src set to host but arp packet set to target

	arp := ether.Payload()
	binary.BigEndian.PutUint16(arp[0:2], 1)                // Hardware Type - Ethernet is 1
	binary.BigEndian.PutUint16(arp[2:4], syscall.ETH_P_IP) // Protocol type - IPv4 0x0800
	b[4] = 6                                               // mac len - fixed
	b[5] = 4                                               // ipv4 len - fixed
	binary.BigEndian.PutUint16(arp[6:8], 0x01)             // operation - 1 request, 2 reply
	copy(arp[8:8+6], sender.MAC[:6])
	copy(arp[14:14+4], sender.IP.AsSlice())
	copy(arp[18:18+6], target.MAC[:6])
	copy(arp[24:24+4], target.IP.AsSlice())
	_, err = h.Conn.WriteTo(ether[:EthHeaderLen+28], &Addr{MAC: dst})
	return err
}

// Notify generates the notification for host offline and online if required. The function
// is only required if the caller wants to receive notifications via the notification channel.
// If the caller is not interested in online/offline transitions, the function is not required to run.
//
// Notify will only send a notification via the notification channel if a change is pending as a result
// of processing the packet. It returns silently if there is no notification pending.
func (h *Session) Notify(frame Frame) {
	if frame.Host == nil {
		if frame.PayloadID != PayloadDHCP4 {
			return
		}
		// Attempt to find a dhcp host entry with saved IP from UpdateDHCP
		frame.SrcAddr.IP = h.DHCPv4IPOffer(frame.SrcAddr.MAC)
		if !frame.SrcAddr.IP.IsValid() {
			return
		}
		frame.Host = h.findIP(frame.SrcAddr.IP)
		if frame.Host == nil {
			return
		}
		// frame.Session.onlineTransition(frame.Host)
		frame.flags = frame.markOnlineTransition()
	}
	h.notify(frame)
}

func (h *Session) notify(frame Frame) {
	frame.Host.MACEntry.Row.RLock()
	if !frame.Host.dirty { // just another IP packet - nothing to do
		frame.Host.MACEntry.Row.RUnlock()
		return
	}

	// if transitioning to online, test if we need to notify previous IP is offline
	offline := []*Host{}
	if frame.onlineTransition() {
		if frame.Host.Addr.IP.Is4() {
			for _, v := range frame.Host.MACEntry.HostList {
				if !v.Online && v.dirty {
					offline = append(offline, v)
				}
			}
		}
	}
	frame.Host.MACEntry.Row.RUnlock()

	// notify previous IP4 is offline
	for _, v := range offline {
		h.makeOffline(v)
	}

	// lock row for update
	frame.Host.MACEntry.Row.Lock()
	notification := toNotification(frame.Host)
	frame.Host.dirty = false
	frame.Host.MACEntry.Row.Unlock()

	h.sendNotification(notification)
}

func (h *Session) makeOffline(host *Host) {
	if Logger.IsInfo() {
		Logger.Msg("IP is offline").Struct(host.Addr).Write()
	}
	host.MACEntry.Row.Lock()
	host.Online = false
	host.dirty = false
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

	// Don't send offline notifications if caller is not reading
	if len(h.C) < cap(h.C) {
		h.sendNotification(notification)
	}
}

// DHCPv4Update updates the mac and host entry with dhcp details.
// A DHCP processing module should call this when it encounters a new host in a DHCP discovery/request message.
//
// A host using DHCP cannot use an IP address until it is confirmed by a dhcp server. Therefore various DHCP messages are
// transmitted with a zero IP and in particular the DHCP discover does not have a srcIP.
func (h *Session) DHCPv4Update(mac net.HardwareAddr, ip netip.Addr, name NameEntry) error {
	if !ip.IsValid() || ip.IsUnspecified() {
		return ErrInvalidIP
	}
	host, _ := h.findOrCreateHostWithLock(Addr{MAC: mac, IP: ip})
	host.UpdateDHCP4Name(name)

	host.MACEntry.Row.Lock()
	defer host.MACEntry.Row.Unlock()

	host.MACEntry.IP4Offer = host.Addr.IP // hack: keep IP to lookup in notify
	if !host.Online {
		h.onlineTransition(host)
	}
	return nil
}

// SetDHCPv4IPOffer set an IPv4 offer for the mac.
// A DCP processing module should call this when it wants to record the IP it has offered for a given mac.
func (h *Session) SetDHCPv4IPOffer(mac net.HardwareAddr, ip netip.Addr, name NameEntry) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	macEntry := h.MACTable.findOrCreate(mac)
	macEntry.IP4Offer = ip
	macEntry.DHCP4Name = name
}

// DHCPv4Offer returns the dhcp v4 ip offer if one is available.
// This is used in the arp spoof module to reject announcements that conflict with the offered dhcp ip.
func (h *Session) DHCPv4IPOffer(mac net.HardwareAddr) netip.Addr {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	if entry, _ := h.MACTable.findMAC(mac); entry != nil {
		return entry.IP4Offer
	}
	return netip.Addr{}
}

// FindMACEntry returns pointer to macEntry or nil if not found
func (h *Session) FindMACEntry(mac net.HardwareAddr) *MACEntry {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	entry, _ := h.MACTable.findMAC(mac)
	return entry
}

// IsCaptured returns true is mac is in capture mode
func (h *Session) IsCaptured(mac net.HardwareAddr) bool {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	if e, _ := h.MACTable.findMAC(mac); e != nil && e.Captured {
		return true
	}
	return false
}

// Capture sets the mac to capture mode
func (h *Session) Capture(mac net.HardwareAddr) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	macEntry := h.MACTable.findOrCreate(mac)
	if macEntry.Captured {
		return nil
	}

	if macEntry.IsRouter {
		return ErrIsRouter
	}
	if Logger.IsInfo() {
		Logger.Msg("captured").MAC("mac", mac).Write()
	}
	macEntry.Captured = true
	return nil
}

// Release sets the mac to normal mode (not captured)
func (h *Session) Release(mac net.HardwareAddr) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	macEntry, _ := h.MACTable.findMAC(mac)
	if macEntry != nil {
		macEntry.Captured = false
		if Logger.IsInfo() {
			Logger.Msg("release").MAC("mac", mac).Write()
		}
	}
	return nil
}

// IPAddrs retun the array of hosts for the mac.
func (h *Session) IPAddrs(mac net.HardwareAddr) []Addr {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	e, _ := h.MACTable.findMAC(mac)
	if e == nil {
		return nil
	}

	list := make([]Addr, 0, len(e.HostList))
	for _, host := range e.HostList {
		list = append(list, host.Addr)
	}
	return list
}
