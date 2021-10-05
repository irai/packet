package engine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	"github.com/irai/packet/dns"
	"github.com/irai/packet/fastlog"
	"github.com/irai/packet/icmp4"
	"github.com/irai/packet/icmp6"
	"golang.org/x/net/bpf"
)

const module = "engine"

// Config has a list of configurable parameters that overide package defaults
type Config struct {
	// Conn enables the client to override the connection with a another packet conn
	// useful for testing
	Conn                    net.PacketConn  // listen connectinon
	NICInfo                 *packet.NICInfo // override nic information - set to non nil to create a test Handler
	FullNetworkScanInterval time.Duration   // Set it to -1 if no scan required
	ProbeInterval           time.Duration   // how often to probe if IP is online
	OfflineDeadline         time.Duration   // mark offline if more than OfflineInte
	PurgeDeadline           time.Duration
}

// buffer holds a raw Ethernet network packet
type buffer struct {
	b [packet.EthMaxSize]byte // buffer
	n int                     // buffer len
}

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler struct {
	session                 *packet.Session // store shared session values
	HandlerIP4              packet.PacketProcessor
	HandlerIP6              packet.PacketProcessor
	ICMP4Handler            icmp4.ICMP4Handler
	ICMP6Handler            icmp6.ICMP6Handler
	DHCP4Handler            dhcp4.DHCP4Handler
	ARPHandler              arp.ARPHandler
	DNSHandler              *dns.DNSHandler
	FullNetworkScanInterval time.Duration // Set it to -1 if no scan required
	ProbeInterval           time.Duration // how often to probe if IP is online
	OfflineDeadline         time.Duration // mark offline if no updates
	PurgeDeadline           time.Duration // purge entry if no updates
	closed                  bool          // set to true when handler is closed
	closeChan               chan bool     // close goroutines channel
	notificationChannel     chan Notification
	dnsChannel              chan dns.DNSEntry
}

// monitorNICFrequency set the frequency to validate NIC is working ok
var monitorNICFrequency = time.Minute * 3

// New creates an ICMPv6 handler with default values
func NewEngine(nic string) (*Handler, error) {
	return Config{}.NewEngine(nic)
}

// NewEngine creates an packet handler with config values
func (config Config) NewEngine(nic string) (*Handler, error) {

	var err error

	h := &Handler{closeChan: make(chan bool)}

	// session holds shared data for all plugins
	h.session = packet.NewEmptySession()
	h.dnsChannel = make(chan dns.DNSEntry, 128)          // plenty of capacity to prevent blocking
	h.notificationChannel = make(chan Notification, 128) // plenty of capacity to prevent blocking

	h.session.NICInfo = config.NICInfo
	if h.session.NICInfo == nil {
		h.session.NICInfo, err = GetNICInfo(nic)
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
	h.session.Conn = config.Conn
	if h.session.Conn == nil {
		h.session.Conn, err = h.setupConn()
		if err != nil {
			return nil, err
		}
	}

	// no plugins to start
	h.ARPHandler = packet.PacketNOOP{}
	h.HandlerIP4 = packet.PacketNOOP{}
	h.HandlerIP6 = packet.PacketNOOP{}
	h.ARPHandler = packet.PacketNOOP{}
	h.ICMP4Handler = icmp4.ICMP4NOOP{}
	h.ICMP6Handler = icmp6.ICMP6NOOP{}
	h.DHCP4Handler = packet.PacketNOOP{}

	// default DNS handler
	h.DNSHandler, _ = dns.New(h.session)

	// create the host entry manually because we don't process host packets
	host, _ := h.session.FindOrCreateHost(packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostIP4.IP})
	host.LastSeen = time.Now().Add(time.Hour * 24 * 365) // never expire
	host.Online = true
	host.MACEntry.Online = true

	// create the router entry manually and set router flag
	host, _ = h.session.FindOrCreateHost(packet.Addr{MAC: h.session.NICInfo.RouterMAC, IP: h.session.NICInfo.RouterIP4.IP})
	host.MACEntry.IsRouter = true
	host.Online = true
	host.MACEntry.Online = true

	return h, nil
}

func (h *Handler) Session() *packet.Session {
	return h.session
}

// Close closes the underlying sockets
func (h *Handler) Close() error {
	if packet.Debug {
		fmt.Println("packet: close() called. closing....")
	}
	h.closed = true

	// Don't close external channels as they will result in a loop in the caller.
	//   i.e. a goroutine waiting on x <-nofificationEngine will return continuosly if the channel is closed

	// close the internal channel to terminate internal goroutines
	close(h.closeChan)
	if h.session.Conn != nil {
		h.session.Conn.Close()
	}
	return nil
}

func (h *Handler) AttachARP(p arp.ARPHandler) {
	h.ARPHandler = p
}

func (h *Handler) DetachARP() error {
	if err := h.ARPHandler.Stop(); err != nil {
		return err
	}
	h.ARPHandler = packet.PacketNOOP{}
	return nil
}

func (h *Handler) AttachICMP4(p icmp4.ICMP4Handler) {
	h.ICMP4Handler = p
}
func (h *Handler) DetachICMP4() error {
	if err := h.ICMP4Handler.Stop(); err != nil {
		return err
	}
	h.ICMP4Handler = icmp4.ICMP4NOOP{}
	return nil
}

func (h *Handler) AttachICMP6(p icmp6.ICMP6Handler) {
	h.ICMP6Handler = p
}
func (h *Handler) DetachICMP6() error {
	if err := h.ICMP6Handler.Stop(); err != nil {
		return err
	}
	h.ICMP6Handler = icmp6.ICMP6NOOP{}
	return nil
}
func (h *Handler) AttachDHCP4(p dhcp4.DHCP4Handler) {
	h.DHCP4Handler = p
}
func (h *Handler) DetachDHCP4() error {
	if err := h.DHCP4Handler.Stop(); err != nil {
		return err
	}
	h.DHCP4Handler = packet.PacketNOOP{}
	return nil
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
	_, err = bpf.Assemble([]bpf.Instruction{
		// Check EtherType
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 80221Q? Virtual LAN over 802.3 Ethernet
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_8021Q, SkipFalse: 1}, // EtherType is 2 pushed out by two bytes
		bpf.LoadAbsolute{Off: 14, Size: 2},
		// IPv4?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_IP, SkipFalse: 1},
		bpf.RetConstant{Val: packet.EthMaxSize},
		// IPv6?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_IPV6, SkipFalse: 1},
		bpf.RetConstant{Val: packet.EthMaxSize},
		// ARP?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_ARP, SkipFalse: 1},
		bpf.RetConstant{Val: packet.EthMaxSize},
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		panic(err)
	}

	// removed bpf filter : June 21
	conn, err = NewServerConn(h.session.NICInfo.IFI, syscall.ETH_P_ALL, SocketConfig{Filter: nil, Promiscuous: true})
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
	h.session.PrintTable()
}

// isUnicastMAC return true if the mac address is unicast
//
// Bit 0 in the first octet is reserved for broadcast or multicast traffic.
// When we have unicast traffic this bit will be set to 0.
// For broadcast or multicast traffic this bit will be set to 1.
func isUnicastMAC(mac net.HardwareAddr) bool {
	return mac[0]&0x01 == 0x00
}

func (h *Handler) startPlugins() error {
	time.Sleep(time.Second * 1) // wait for reader to start

	if err := h.HandlerIP4.Start(); err != nil {
		fmt.Println("error: in IP4 start:", err)
	}
	if err := h.HandlerIP6.Start(); err != nil {
		fmt.Println("error: in IP6 start:", err)
	}
	if err := h.ICMP4Handler.Start(); err != nil {
		fmt.Println("error: in ICMP4 start:", err)
	}
	if err := h.ICMP6Handler.Start(); err != nil {
		fmt.Println("error: in ICMP6 start:", err)
	}
	if err := h.ARPHandler.Start(); err != nil {
		fmt.Println("error: in ARP start:", err)
	}
	if err := h.DHCP4Handler.Start(); err != nil {
		fmt.Println("error: in DHCP4 start:", err)
	}

	h.DNSHandler.Start()

	return nil
}

func (h *Handler) stopPlugins() error {
	if err := h.HandlerIP4.Stop(); err != nil {
		fmt.Println("error: in IP4 stop:", err)
	}
	if err := h.HandlerIP6.Stop(); err != nil {
		fmt.Println("error: in IP6 stop:", err)
	}
	if err := h.ICMP4Handler.Stop(); err != nil {
		fmt.Println("error: in ICMP4 stop:", err)
	}
	if err := h.ICMP6Handler.Stop(); err != nil {
		fmt.Println("error: in ICMP6 stop:", err)
	}
	if err := h.ARPHandler.Stop(); err != nil {
		fmt.Println("error: in ARP stop:", err)
	}
	if err := h.DHCP4Handler.Stop(); err != nil {
		fmt.Println("error: in DHCP4 stop:", err)
	}
	return nil
}

func (h *Handler) FindIP6Router(ip net.IP) icmp6.Router {
	return h.ICMP6Handler.FindRouter(ip)
}

var stpCount int
var stpNextLog time.Time

// process8023Frame handle general layer 2 packets in Ethernet 802.3 format.
//
// see https://macaddress.io/faq/how-to-recognise-an-ieee-802-1x-mac-address-application
// see https://networkengineering.stackexchange.com/questions/64757/unknown-ethertype
// see https://www.mit.edu/~map/Ethernet/multicast.html
func (h *Handler) process8023Frame(ether packet.Ether) {
	llc := packet.LLC(ether.Payload())
	if err := llc.IsValid(); err != nil {
		fmt.Printf("packet: err invalid LLC err=%s\n", err)
		return
	}

	// SONOS - LLC, dsap STP (0x42) Individual, ssap STP (0x42) Command
	// uses "01:80:c2:00:00:00" destination MAC
	// http://www.netrounds.com/wp-content/uploads/public/layer-2-control-protocol-handling.pdf
	// https://techhub.hpe.com/eginfolib/networking/docs/switches/5980/5200-3921_l2-lan_cg/content/499036672.htm#:~:text=STP%20protocol%20frames%20STP%20uses%20bridge%20protocol%20data,devices%20exchange%20BPDUs%20to%20establish%20a%20spanning%20tree.
	if llc.DSAP() == 0x42 && llc.SSAP() == 0x42 {
		stpCount++
		now := time.Now()
		if stpNextLog.Before(now) {
			// fmt.Printf("packet: LLC STP protocol %s %s count=%d payload=[% x]\n", ether, llc, stpCount, ether[:])
			fastlog.NewLine(module, "LLC STP protocol").Struct(ether).Struct(llc).Int("count", stpCount).ByteArray("payload", ether.Payload()).Write()
			stpNextLog = now.Add(time.Minute * 5)
		}
		return
	}

	if llc.DSAP() == 0xaa && llc.SSAP() == 0xaa && llc.Control() == 0x03 {
		snap := packet.SNAP(llc)
		if err := snap.IsValid(); err != nil {
			fmt.Printf("packet: err invalid SNAP packet err=%s\n", err)
			return
		}
		// fmt.Printf("packet: LLC SNAP protocol %s %s payload=[% x]\n", ether, snap, ether[:])
		fastlog.NewLine(module, "LLC SNAP protocol").Struct(ether).Struct(snap).ByteArray("payload", ether.Payload()).Write()
		return
	}

	if llc.DSAP() == 0xe0 && llc.SSAP() == 0xe0 {
		fastlog.NewLine(module, "IPX protocol").Struct(ether).ByteArray("payload", ether.Payload()).Write()
		return
	}

	// wifi mac notification -
	// To see these:
	//    sudo tcpdump -vv -x not ip6 and not ip and not arp
	//    then switch a mobile phone to airplane mode to force a network reconnect
	fmt.Printf("packet: rcvd 802.3 LLC frame %s %s payload=[% x]\n", ether, llc, ether[:])
}

func (h *Handler) processUDP(host *packet.Host, ether packet.Ether, udp packet.UDP) (*packet.Host, bool, error) {
	udpSrcPort := udp.SrcPort()
	udpDstPort := udp.DstPort()
	var err error
	var notify bool
	var result packet.Result

	switch {
	case udpSrcPort == 443 || udpDstPort == 443:
		// ssl udp - likely quic?
		// do nothing
		return host, false, nil

	case udpDstPort == packet.DHCP4ServerPort || udpDstPort == packet.DHCP4ClientPort: // DHCP4 packet?
		if result, err = h.DHCP4Handler.ProcessPacket(host, ether, udp.Payload()); err != nil {
			fmt.Printf("packet: error processing dhcp4: %s\n", err)
		}
		if result.Update {
			if result.IsRouter { // IsRouter is true if this is a new host from a DHCP request
				host, _ = h.session.FindOrCreateHost(result.FrameAddr)
			}
			if h.lockAndProcessDHCP4Update(host, result) {
				notify = true
			}
		}

	case udpDstPort == 546 || udpDstPort == 547: // DHCP6
		fastlog.NewLine("ether", "dhcp6 packet").Struct(ether).LF().Module("udp", "dhcp6 packet").Struct(udp).Write()
		fastlog.NewLine("packet", "ignore dhcp6 packet").ByteArray("payload", udp.Payload()).Write()

	case udpSrcPort == 53: // DNS response
		dnsEntry, err := h.DNSHandler.ProcessDNS(host, ether, udp.Payload())
		if err != nil {
			fmt.Printf("packet: error processing dns: %s\n", err)
			break
		}
		if dnsEntry.Name != "" {
			h.sendDNSNotification(dnsEntry)
		}

	case udpDstPort == 53: // DNS request
	// do nothing

	case udpSrcPort == 5353 || udpDstPort == 5353: // Multicast DNS (MDNS)
		if host != nil {
			ipv4Name, ipv6Name, err := h.DNSHandler.ProcessMDNS(host, ether, udp.Payload())
			if err != nil {
				fmt.Printf("packet: error processing mdns: %s\n", err)
				break
			}
			ipv4Name.NameEntry, notify = host.MDNSName.Merge(ipv4Name.NameEntry)
			if notify {
				host.MACEntry.Row.Lock()
				host.MDNSName = ipv4Name.NameEntry
				fastlog.NewLine(module, "updated mdns name").Struct(host.Addr).Struct(host.MDNSName).Write()
				host.MACEntry.MDNSName, _ = host.MACEntry.MDNSName.Merge(host.MDNSName)
				host.MACEntry.Row.Unlock()
			}

			for _, v := range ipv6Name {
				fastlog.NewLine(module, "mdns ipv6 ignoring host").Struct(v).Write()
			}
		}

	case udpSrcPort == 5355 || udpDstPort == 5355:
		// Link Local Multicast Name Resolution (LLMNR)
		fastlog.NewLine(module, "ether").Struct(ether).Module(module, "received llmnr packet").Struct(host).Write()
		if host != nil {
			ipv4Name, ipv6Names, err := h.DNSHandler.ProcessMDNS(host, ether, udp.Payload())
			if err != nil {
				fmt.Printf("packet: error processing mdns: %s\n", err)
				break
			}
			ipv4Name.NameEntry, notify = host.LLMNRName.Merge(ipv4Name.NameEntry)
			if notify {
				host.MACEntry.Row.Lock()
				host.LLMNRName = ipv4Name.NameEntry
				fastlog.NewLine(module, "updated llmnr name").Struct(host.Addr).Struct(host.LLMNRName).Write()
				host.MACEntry.LLMNRName, _ = host.MACEntry.LLMNRName.Merge(host.LLMNRName)
				host.MACEntry.Row.Unlock()
			}
			for _, v := range ipv6Names {
				fastlog.NewLine(module, "mdns ipv6 ignoring host").Struct(v).Write()
			}
		}

	case udpSrcPort == 123:
		// Network time synchonization protocol
		// do nothing
		fastlog.NewLine(module, "NTP frame").Struct(ether).Write()

	case udpDstPort == 1900:
		// Microsoft Simple Service Discovery Protocol
		if host != nil {
			nameEntry, location, err := h.DNSHandler.ProcessSSDP(host, ether, udp.Payload())
			if err != nil {
				fastlog.NewLine(module, "error processing ssdp").Error(err).Write()
				break
			}

			// Update SSDPName if modified
			nameEntry, notify = host.SSDPName.Merge(nameEntry)
			if notify {
				host.MACEntry.Row.Lock()
				host.SSDPName = nameEntry
				fastlog.NewLine(module, "updated ssdp name").Struct(host.Addr).Struct(host.SSDPName).Write()
				host.MACEntry.SSDPName, _ = host.MACEntry.SSDPName.Merge(host.SSDPName)
				host.MACEntry.Row.Unlock()
			}

			// Retrieve service details if valid location
			// Location is the end point for the UPNP service discovery
			// Retrieve in a goroutine
			if location != "" {
				go func(host *packet.Host) {
					host.MACEntry.Row.RLock()
					if host.SSDPName.Expire.After(time.Now()) { // ignore if cache is valid
						host.MACEntry.Row.RUnlock()
						return
					}
					host.MACEntry.Row.RUnlock()
					nameEntry, err := h.DNSHandler.UPNPServiceDiscovery(host.Addr, location)
					if err != nil {
						fastlog.NewLine("engine", "error retrieving UPNP service discovery").String("location", location).Error(err).Write()
						return
					}
					var notify bool
					host.MACEntry.Row.Lock()
					host.SSDPName, notify = host.SSDPName.Merge(nameEntry)
					if notify {
						fastlog.NewLine(module, "updated ssdp name").Struct(host.Addr).Struct(host.SSDPName).Write()
						host.MACEntry.SSDPName, _ = host.MACEntry.SSDPName.Merge(host.SSDPName)
					}
					host.MACEntry.Row.Unlock()
					if notify {
						h.sendNotification(toNotification(host))
					}
				}(host)
				break
			}
		}

	case udpDstPort == 3702:
		// Web Services Discovery Protocol (WSD)
		fastlog.NewLine(module, "ether").Struct(ether).Struct(udp).Struct(host).Write()
		fastlog.NewLine(module, "wsd frame").String("payload", string(udp.Payload())).Write()

	case udpDstPort == 137 || udpDstPort == 138:
		// Netbions NBNS
		entry, err := h.DNSHandler.ProcessNBNS(host, ether, udp.Payload())
		if err != nil {
			fastlog.NewLine(module, "error processing nbns").Error(err).Write()
			break
		}
		if entry.Name != "" {
			host.MACEntry.Row.Lock()
			host.NBNSName, notify = host.NBNSName.Merge(entry)
			if notify {
				fastlog.NewLine(module, "updated nbns name").Struct(host.Addr).Struct(host.NBNSName).Write()
				host.MACEntry.NBNSName, notify = host.MACEntry.NBNSName.Merge(host.NBNSName)
			}
			host.MACEntry.Row.Unlock()
		}

	case udpDstPort == 32412 || udpDstPort == 32414:
		// Plex application multicast on these ports to find players.
		// G'Day Mate (GDM) multicast packets
		// https://github.com/NineWorlds/serenity-android/wiki/Good-Day-Mate
		fastlog.NewLine(module, "plex frame").Struct(ether).IP("srcip", ether.SrcIP()).IP("dstip", ether.DstIP()).ByteArray("payload", udp.Payload()).Write()

	case udpSrcPort == 10001 || udpDstPort == 10001:
		// Ubiquiti device discovery protocol
		// https://help.ui.com/hc/en-us/articles/204976244-EdgeRouter-Ubiquiti-Device-Discovery
		fastlog.NewLine("proto", "ubiquiti device discovery").Struct(ether).IP("srcip", ether.SrcIP()).IP("dstip", ether.DstIP()).ByteArray("udp", udp).Write()

	default:
		// don't log if getting too many packets
		if now := time.Now(); invalidUDPNextLog.Before(now) {
			invalidUDPNextLog = now.Add(time.Minute * 5)
			fastlog.NewLine("proto", "unexpected udp type").Struct(ether).Struct(udp).Struct(host).Write()
		}
	}

	return host, notify, nil
}

var invalidUDPNextLog time.Time // hack to print udp logs every few minutes only
var count0x880a int

func (h *Handler) processPacket(ether packet.Ether) (err error) {
	var d1, d2, d3 time.Duration

	startTime := time.Now()

	// In order to allow Ethernet II and IEEE 802.3 framing to be used on the same Ethernet segment,
	// a unifying standard, IEEE 802.3x-1997, was introduced that required that EtherType values be greater than or equal to 1536.
	// Thus, values of 1500 and below for this field indicate that the field is used as the size of the payload of the Ethernet frame
	// while values of 1536 and above indicate that the field is used to represent an EtherType.
	if ether.EtherType() < 1536 {
		h.process8023Frame(ether)
		return nil
	}

	notify := false
	var ip4Frame packet.IP4
	var ip6Frame packet.IP6
	var l4Proto int
	var l4Payload []byte
	var host *packet.Host
	var result packet.Result

	// Everything from here is encapsulated in an Ethernet II frame format
	// First, lets process layer 3 - IP4, IP6, ARP and some weird protocols
	//
	// This will set the variable host if the sender is a local IP and not multicast.
	switch ether.EtherType() {
	case syscall.ETH_P_IP: // 0x0800
		ip4Frame = packet.IP4(ether.Payload())
		if !ip4Frame.IsValid() {
			fmt.Println("packet: error invalid ip4 frame type=", ether.EtherType())
			return nil
		}
		if packet.DebugIP4 {
			fastlog.NewLine("ether", "").Struct(ether).LF().Module("ip4", "").Struct(ip4Frame).Write()
		}

		// Create host only if on same subnet
		// Note: DHCP request for previous discover have zero src IP; therefore wont't create host entry here.
		ip := ip4Frame.Src() // avoid []byte allocation when used twice below
		if h.session.NICInfo.HostIP4.Contains(ip) {
			host, _ = h.session.FindOrCreateHost(packet.Addr{MAC: ether.Src(), IP: ip}) // will lock/unlock
		}
		l4Proto = ip4Frame.Protocol()
		l4Payload = ip4Frame.Payload()

	case syscall.ETH_P_IPV6: // 0x86dd
		ip6Frame = packet.IP6(ether.Payload())
		if !ip6Frame.IsValid() {
			fmt.Println("packet: error invalid ip6 frame type=", ether.EtherType())
			return nil
		}
		if packet.DebugIP6 {
			fastlog.NewLine("ether", "").Struct(ether).LF().Module("ip6", "").Struct(ip6Frame).Write()
			// fastlog.Strings("packet: ether ", ether.String())
			// fastlog.Strings("packet: ip6 ", ip6Frame.String())
		}

		l4Proto = ip6Frame.NextHeader()
		l4Payload = ip6Frame.Payload()

		// create host only if src IP is:
		//     - unicast local link address (i.e. fe80::)
		//     - global IP6 sent by a local host not the router
		//
		// We ignore IP6 packets forwarded by the router to a local host using a Global Unique Addresses.
		// For example, an IP6 google search will be forwared by the router as:
		//    ip6 src=google.com dst=GUA localhost and srcMAC=routerMAC dstMAC=localHostMAC
		// TODO: is it better to check if IP is in the prefix?
		if ip6Frame.Src().IsLinkLocalUnicast() ||
			(ip6Frame.Src().IsGlobalUnicast() && !bytes.Equal(ether.Src(), h.session.NICInfo.RouterMAC)) {
			host, _ = h.session.FindOrCreateHost(packet.Addr{MAC: ether.Src(), IP: ip6Frame.Src()}) // will lock/unlock
		}

		// IPv6 Hop by Hop extension - always the first header if present
		if l4Proto == syscall.IPPROTO_HOPOPTS {
			header := packet.HopByHopExtensionHeader(l4Payload)
			if !header.IsValid() {
				fmt.Printf("packet: error invalid next header payload=%d ext=%d\n", len(l4Payload), len(ether))
				return nil
			}
			if n, err := h.session.ProcessIP6HopByHopExtension(host, ether, l4Payload); err != nil || n <= 0 {
				fmt.Printf("packet: error processing hop by hop extension : %s\n", err)
			}
			if len(l4Payload) <= header.Len()+1 {
				fmt.Printf("packet: error invalid next header payload=%d ext=%d\n", len(l4Payload), header.Len()+2)
				return nil
			}
			l4Proto = header.NextHeader()
			l4Payload = l4Payload[header.Len():]
		}

	case syscall.ETH_P_ARP: // 0x806
		l4Proto = 0 // skip layer 4 processing below
		if result, err = h.ARPHandler.ProcessPacket(host, ether, ether.Payload()); err != nil {
			fmt.Printf("packet: error processing arp: %s\n", err)
		}
		if result.Update {
			host, _ = h.session.FindOrCreateHost(result.FrameAddr)
		}

	case 0x8808: // Ethernet flow control - Pause frame
		// An overwhelmed network node can send a pause frame, which halts the transmission of the sender for a specified period of time.
		// EtherType 0x8808 is used to carry the pause command, with the Control opcode set to 0x0001 (hexadecimal).
		// When a station wishes to pause the other end of a link, it sends a pause frame to either the unique
		// 48-bit destination address of this link or to the 48-bit reserved multicast address of 01-80-C2-00-00-01.
		// A likely scenario is network congestion within a switch.
		p := packet.EthernetPause(ether.Payload())
		if err := p.IsValid(); err != nil {
			fastlog.NewLine(module, "invalid Ethernet pause frame").Error(err).ByteArray("frame", ether).Write()
			return nil
		}
		fastlog.NewLine(module, "ether").Struct(ether).Module(module, "ethernet flow control frame").Struct(p).Write()
		return nil

	case 0x8899: // Realtek Remote Control Protocol (RRCP)
		// This protocol allows an expernal application to control a dumb switch.
		// TODO: Need to investigate this
		// https://andreas.jakum.net/blog/2012/10/27/rrcp-realtek-remote-control-protocol
		// Realtek's RTL8316B, RTL8324, RTL8326 and RTL8326S are supported
		//
		// See frames here:
		// http://realtek.info/pdf/rtl8324.pdf  page 43
		//
		// fmt.Printf("packet: RRCP frame %s payload=[% x]\n", ether, ether[:])
		fastlog.NewLine(module, "ether").Struct(ether).Module(module, "RRCP frame").ByteArray("payload", ether.Payload()).Write()
		return nil

	case 0x88cc: // Link Layer Discovery Protocol (LLDP)
		// not sure if we will ever receive these in a home LAN!
		// fmt.Printf("packet: LLDP frame %s payload=[% x]\n", ether, ether[:])
		p := packet.LLDP(ether.Payload())
		if err := p.IsValid(); err != nil {
			fastlog.NewLine(module, "invalid LLDP frame").Error(err).ByteArray("frame", ether).Write()
			return nil
		}
		fastlog.NewLine(module, "ether").Struct(ether).Module(module, "LLDP").Struct(p).Write()
		return nil

	case 0x890d: // Fast Roaming Remote Request (802.11r)
		// Fast roaming, also known as IEEE 802.11r or Fast BSS Transition (FT),
		// allows a client device to roam quickly in environments implementing WPA2 Enterprise security,
		// by ensuring that the client device does not need to re-authenticate to the RADIUS server
		// every time it roams from one access point to another.
		// fmt.Printf("packet: 802.11r Fast Roaming frame %s payload=[% x]\n", ether, ether[:])
		fastlog.NewLine(module, "ether").Struct(ether).Module(module, "802.11r Fast Roaming frame").ByteArray("payload", ether.Payload()).Write()
		return nil

	case 0x893a: // IEEE 1905.1 - network enabler for home networking
		// Enables topology discovery, link metrics, forwarding rules, AP auto configuration
		// TODO: investigate how to use IEEE 1905.1
		// See:
		// https://grouper.ieee.org/groups/802/1/files/public/docs2012/802-1-phkl-P1095-Tech-Presentation-1207-v01.pdf
		p := packet.IEEE1905(ether.Payload())
		if err := p.IsValid(); err != nil {
			fastlog.NewLine(module, "invalid IEEE 1905 frame").Error(err).ByteArray("frame", ether).Write()
			return nil
		}
		fastlog.NewLine(module, "ether").Struct(ether).Module(module, "IEEE 1905.1 frame").Struct(p).Write()
		return nil

	case 0x6970: // Sonos Data Routing Optimisation
		// References to type EthType 0x6970 appear in a Sonos patent
		// https://portal.unifiedpatents.com/patents/patent/US-20160006778-A1
		fastlog.NewLine(module, "ether").Struct(ether).Module(module, "Sonos data routing frame").ByteArray("payload", ether.Payload()).Write()
		return nil

	case 0x880a: // Unknown protocol - but commonly seen in logs
		if (count0x880a % 32) == 0 {
			fastlog.NewLine(module, "unknown 0x880a frame").Int("count", count0x880a).ByteArray("payload", ether.Payload()).Write()
		}
		count0x880a++
		return nil

	default:
		// fmt.Printf("packet: error invalid ethernet type %s\n", ether)
		fastlog.NewLine(module, "unexpected ethernet type").Struct(ether).ByteArray("payload", ether.Payload()).Write()
		return nil
	}
	d1 = time.Since(startTime)

	// Process level 4 and 5 protocols: ICMP4, ICMP6, IGMP, TCP, UDP, DHCP4, DNS
	//
	switch l4Proto {
	case 0:
		// Do nothing; likely ARP

	case syscall.IPPROTO_TCP:
		if ip4Frame != nil {
			tcp := packet.TCP(ip4Frame.Payload())

			// During connection establishement (SYN), test if we have the host name
			// in case the client is using an ip we don't know about
			// perform a PTR lookup to attempt to discover the name
			if tcp.SYN() && !h.session.NICInfo.HomeLAN4.Contains(ip4Frame.Dst()) {
				if !h.DNSHandler.DNSExist(ip4Frame.NetaddrDst()) {
					fmt.Printf("packet: dns entry does not exist for ip=%s\n", ip4Frame.Dst())
					go h.DNSHandler.DNSLookupPTR(ip4Frame.NetaddrDst())
				}
			}
		}

	case syscall.IPPROTO_UDP: // 0x11
		udp := packet.UDP(l4Payload)
		if !udp.IsValid() {
			fmt.Println("packet: error invalid udp frame ", ip4Frame)
			return nil
		}
		if packet.DebugUDP {
			if ip4Frame != nil {
				fastlog.NewLine("ether", "").Struct(ether).LF().Module("ip4", "").Struct(ip4Frame).Module("udp", "").Struct(udp).Write()
			} else {
				fastlog.NewLine("ether", "").Struct(ether).LF().Module("ip6", "").Struct(ip6Frame).Module("udp", "").Struct(udp).Write()
			}
		}
		if host, notify, err = h.processUDP(host, ether, udp); err != nil {
			fastlog.NewLine("packet", "error processing udp").Error(err).Write()
			return nil
		}

	case syscall.IPPROTO_ICMP:
		if result, err = h.ICMP4Handler.ProcessPacket(host, ether, l4Payload); err != nil {
			fmt.Printf("packet: error processing icmp4: %s\n", err)
		}

	case syscall.IPPROTO_ICMPV6: // 0x03a
		if result, err = h.ICMP6Handler.ProcessPacket(host, ether, l4Payload); err != nil {
			fmt.Printf("packet: error processing icmp6 : %s\n", err)
		}
		if result.Update {
			if result.FrameAddr.IP != nil {
				host, _ = h.session.FindOrCreateHost(result.FrameAddr)
			}
			if host != nil {
				host.MACEntry.IsRouter = result.IsRouter
				notify = true
			}
		}

	case syscall.IPPROTO_IGMP:
		// Internet Group Management Protocol - Ipv4 multicast groups
		// do nothing
		fmt.Printf("packet: ipv4 igmp packet %s\n", ether)

	default:
		fmt.Println("packet: unsupported level 4 header", l4Proto, ether)
	}
	d2 = time.Since(startTime)

	if host != nil {
		h.lockAndSetOnline(host, notify)
	}

	d3 = time.Since(startTime)
	if d3 > time.Microsecond*600 {
		fastlog.NewLine("packet", "warning > 600 microseconds").String("l3", d1.String()).String("l4", d2.String()).String("total", d3.String()).
			Int("l4proto", l4Proto).Uint16Hex("ethertype", ether.EtherType()).Write()
	}
	return nil
}

// ListenAndServe listen for raw packets and invoke hooks as required
func (h *Handler) ListenAndServe(ctxt context.Context) (err error) {

	// start all plugins with delay
	go h.startPlugins()
	defer h.stopPlugins()

	// minute ticker
	go h.minuteLoop()

	// Implement a single worker pattern to process packets async to the reader. This pattern
	// ensure we are reading packets as fast as possible despite the processing time of the worker.
	//
	// A single worker will ensure packets are processed in order received but
	// queue must be sufficiently large to accommodate the worker occasionally taking too long.
	const packetQueueLen = 512
	var packetBuf = sync.Pool{New: func() interface{} { return new(buffer) }}
	packetQueue := make(chan *buffer, packetQueueLen)
	go func() {
		for {
			buf, ok := <-packetQueue
			if !ok {
				fastlog.NewLine(module, "packet worker goroutine terminating")
				return
			}
			ether := packet.Ether(buf.b[:buf.n])
			h.processPacket(ether)
			packetBuf.Put(buf)
		}
	}()

	// Setup a nic monitoring goroutine to ensure we always receive IP packets.
	// If the switch port is disabled or the the nic stops receiving packets for any reason,
	// our best option is to stop the engine and likely restart.
	//
	var ipHeartBeat uint32 // ipHeartBeat is set to 1 when we receive an IP packet.
	go func() {
		for {
			time.Sleep(monitorNICFrequency)
			if atomic.LoadUint32(&ipHeartBeat) == 0 {
				fmt.Printf("fatal: failed to receive ip packets in duration=%s - sending sigterm time=%v\n", monitorNICFrequency, time.Now())
				// Send sigterm to terminate process
				syscall.Kill(os.Getpid(), syscall.SIGTERM)
			}
			atomic.StoreUint32(&ipHeartBeat, 0)
		}
	}()

	for {
		buf := packetBuf.Get().(*buffer)
		if err = h.session.Conn.SetReadDeadline(time.Now().Add(time.Second * 2)); err != nil {
			if h.closed { // closed by call to h.Close()?
				close(packetQueue)
				return nil
			}
			return fmt.Errorf("setReadDeadline error: %w", err)
		}

		buf.n, _, err = h.session.Conn.ReadFrom(buf.b[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			if h.closed { // closed by call to h.Close()?
				return nil
			}
			return fmt.Errorf("read error: %w", err)
		}

		ether := packet.Ether(buf.b[:buf.n])
		if err := ether.IsValid(); err != nil {
			fastlog.NewLine(module, "invalid ethernet packet").ByteArray("frame", ether).Write()
			continue
		}

		// Ignore packets sent via our interface
		// If we don't have this, then we received all forwarded packets with client IPs containing our host mac
		//
		// TODO: should this be in the bpf rules?
		if bytes.Equal(ether.Src(), h.session.NICInfo.HostMAC) {
			continue
		}

		// Only interested in unicast ethernet
		if !isUnicastMAC(ether.Src()) {
			continue
		}

		if len(packetQueue) >= packetQueueLen {
			// Send sigterm to terminate process
			fastlog.NewLine(module, "error packet queue exceeded maximum limit - deadlock?").Write()
			syscall.Kill(os.Getpid(), syscall.SIGTERM)
			packetBuf.Put(buf)
			return packet.ErrNoReader
		}

		if len(packetQueue) > 16 {
			fastlog.NewLine(module, "packet queue").Int("len", len(packetQueue)).Write()
		}

		if ether.EtherType() == syscall.ETH_P_IP || ether.EtherType() == syscall.ETH_P_IPV6 {
			atomic.StoreUint32(&ipHeartBeat, 1)
		}

		// wakeup worker
		packetQueue <- buf
	}
}
