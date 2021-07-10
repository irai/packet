package engine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	"github.com/irai/packet/dns"
	"github.com/irai/packet/icmp4"
	"github.com/irai/packet/icmp6"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"
)

// Config has a list of configurable parameters that overide package defaults
type Config struct {
	// Conn enables the client to override the connection with a another packet conn
	// useful for testing
	Conn                    net.PacketConn  // listen connectinon
	NICInfo                 *packet.NICInfo // override nic information - set to non nil to create a test Handler
	FullNetworkScanInterval time.Duration   // Set it to zero if no scan required
	ProbeInterval           time.Duration   // how often to probe if IP is online
	OfflineDeadline         time.Duration   // mark offline if more than OfflineInte
	PurgeDeadline           time.Duration
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
	forceScan               bool
	serviceDiscoveryChan    chan discoverAction // channel used for delayed service discovery
}

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
	h.dnsChannel = make(chan dns.DNSEntry, 64)           // plenty of capacity to prevent blocking
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

	// create service discovery goroutine
	h.serviceDiscoveryChan = make(chan discoverAction, 32)

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

func (h *Handler) DetachARP() {
	h.ARPHandler = packet.PacketNOOP{}
}

func (h *Handler) AttachICMP4(p icmp4.ICMP4Handler) {
	h.ICMP4Handler = p
}
func (h *Handler) DetachICMP4() {
	h.ICMP4Handler = icmp4.ICMP4NOOP{}
}

func (h *Handler) AttachICMP6(p icmp6.ICMP6Handler) {
	h.ICMP6Handler = p
}
func (h *Handler) DetachICMP6() {
	h.ICMP6Handler = icmp6.ICMP6NOOP{}
}
func (h *Handler) AttachDHCP4(p dhcp4.DHCP4Handler) {
	h.DHCP4Handler = p
}
func (h *Handler) DetachDHCP4() {
	h.DHCP4Handler = packet.PacketNOOP{}
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
		log.Fatal("bpf assemble error", err)
	}

	bpf = nil // remove bpf test - June 2021

	// see: https://www.man7.org/linux/man-pages/man7/packet.7.html
	conn, err = NewServerConn(h.session.NICInfo.IFI, syscall.ETH_P_ALL, SocketConfig{Filter: bpf, Promiscuous: true})
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

func (h *Handler) serviceDiscoveryLoop() {
	for {
		select {
		case action := <-h.serviceDiscoveryChan:
			notification, err := h.upnpServiceDiscovery(action)
			if err != nil {
				fmt.Printf("engine: error in service discovery %s location=%s error=%s\n", action.addr, action.location, err)
				continue
			}
			if notification.UPNPName != "" {
				if packet.Debug {
					fmt.Printf("engine: sending upnp notification %s\n", notification)
				}
				h.sendNotification(notification)
			}
		case <-h.closeChan:
			return
		}
	}
}

func (h *Handler) FindIP6Router(ip net.IP) icmp6.Router {
	return h.ICMP6Handler.FindRouter(ip)
}

// ListenAndServe listen for raw packets and invoke hooks as required
func (h *Handler) ListenAndServe(ctxt context.Context) (err error) {

	// start all plugins with delay
	go h.startPlugins()
	defer h.stopPlugins()

	// minute ticker
	go h.minuteLoop()

	// service discovery goroutine
	go h.serviceDiscoveryLoop()

	var d1, d2, d3 time.Duration
	var startTime time.Time
	buf := make([]byte, packet.EthMaxSize)
	for {
		if err = h.session.Conn.SetReadDeadline(time.Now().Add(time.Second * 2)); err != nil {
			if h.closed { // closed by call to h.Close()?
				return nil
			}
			return fmt.Errorf("setReadDeadline error: %w", err)
		}

		n, _, err := h.session.Conn.ReadFrom(buf)
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

		ether := packet.Ether(buf[:n])
		if !ether.IsValid() {
			log.Error("icmp invalid ethernet packet ", ether.EtherType())
			continue
		}

		// Ignore packets sent via our interface
		// If we don't have this, then we received all forwarded packets with client IPs containing our host mac
		//
		// TODO: should this be in the bpf rules?
		if bytes.Equal(ether.Src(), h.session.NICInfo.HostMAC) {
			continue
		}
		// fmt.Println("DEBUG ether ", ether)

		// Only interested in unicast ethernet
		if !isUnicastMAC(ether.Src()) {
			continue
		}

		// In order to allow Ethernet II and IEEE 802.3 framing to be used on the same Ethernet segment,
		// a unifying standard, IEEE 802.3x-1997, was introduced that required that EtherType values be greater than or equal to 1536.
		// Thus, values of 1500 and below for this field indicate that the field is used as the size of the payload of the Ethernet frame
		// while values of 1536 and above indicate that the field is used to represent an EtherType.
		// see https://macaddress.io/faq/how-to-recognise-an-ieee-802-1x-mac-address-application
		// see https://networkengineering.stackexchange.com/questions/64757/unknown-ethertype
		// see https://www.mit.edu/~map/Ethernet/multicast.html
		if ether.EtherType() < 1536 {

			llc := packet.LLC(ether.Payload())
			// SONOS - LLC, dsap STP (0x42) Individual, ssap STP (0x42) Command
			// uses "01:80:c2:00:00:00" destination MAC
			// http://www.netrounds.com/wp-content/uploads/public/layer-2-control-protocol-handling.pdf

			// wifi mac notification -
			// To see these:
			//    sudo tcpdump -vv -x not ip6 and not ip and not arp
			//    then switch a mobile phone to airplane mode to force a network reconnect
			if false {
				fmt.Printf("packet: rcvd 802.3 frame %s\n", llc)
			}
			continue
		}

		notify := false
		var ip4Frame packet.IP4
		var ip6Frame packet.IP6
		var l4Proto int
		var l4Payload []byte
		var host *packet.Host
		var result packet.Result

		// Process layer 3 - IP4, IP6 and ARP
		//
		// This will set host if the sender is a local IP and not multicast.
		switch ether.EtherType() {
		case syscall.ETH_P_IP: // 0x0800
			ip4Frame = packet.IP4(ether.Payload())
			if !ip4Frame.IsValid() {
				fmt.Println("packet: error invalid ip4 frame type=", ether.EtherType())
				continue
			}
			if packet.DebugIP4 {
				fmt.Println("packet: ether", ether)
				fmt.Println("packet: ip4", ip4Frame)
			}

			// Create host only if on same subnet
			// Note: DHCP request for previous discover have zero src IP; therefore wont't create host entry here.
			if h.session.NICInfo.HostIP4.Contains(ip4Frame.Src()) {
				host, _ = h.session.FindOrCreateHost(packet.Addr{MAC: ether.Src(), IP: ip4Frame.Src()}) // will lock/unlock
			}
			l4Proto = ip4Frame.Protocol()
			l4Payload = ip4Frame.Payload()

		case syscall.ETH_P_IPV6: // 0x86dd
			ip6Frame = packet.IP6(ether.Payload())
			if !ip6Frame.IsValid() {
				fmt.Println("packet: error invalid ip6 frame type=", ether.EtherType())
				continue
			}
			if packet.DebugIP6 {
				fmt.Printf("packet: ether %s\n", ether)
				fmt.Printf("packet: ip6 %s\n", ip6Frame)
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
					fmt.Printf("packet: error invalid next header payload=%d ext=%d\n", len(l4Payload), n)
					continue
				}
				if n, err = h.session.ProcessIP6HopByHopExtension(host, ether, l4Payload); err != nil || n <= 0 {
					fmt.Printf("packet: error processing hop by hop extension : %s\n", err)
				}
				if len(l4Payload) <= header.Len()+1 {
					fmt.Printf("packet: error invalid next header payload=%d ext=%d\n", len(l4Payload), header.Len()+2)
					continue
				}
				l4Proto = header.NextHeader()
				l4Payload = l4Payload[header.Len():]
			}

		case syscall.ETH_P_ARP: // 0x806
			l4Proto = syscall.ETH_P_ARP // treat arp as l4 proto; similar to IP6 ICMP NDP

		case 0x8899: // Realtek Remote Control Protocol (RRCP)
			// This protocol allows an expernal application to control a dumb switch.
			// TODO: Need to investigate this
			// https://andreas.jakum.net/blog/2012/10/27/rrcp-realtek-remote-control-protocol
			// Realtek's RTL8316B, RTL8324, RTL8326 and RTL8326S are supported
			//
			// See frames here:
			// http://realtek.info/pdf/rtl8324.pdf  page 43
			//
			fmt.Printf("packet: RRCP frame %s payload=\"% x\"\n", ether, ether.Payload())
			continue

		case 0x88cc: // Link Layer Discovery Protocol (LLDP)
			// not sure if we will ever receive these in a home LAN!
			fmt.Printf("packet: LLDP frame %s payload=\"% x\"\n", ether, ether.Payload())
			continue

		default:
			fmt.Printf("packet: error invalid ethernet type %s\n", ether)
			continue
		}
		d1 = time.Since(startTime)

		// Process level 4 and 5 protocols: ICMP4, ICMP6, IGMP, TCP, UDP, DHCP4, DNS
		//
		switch l4Proto {
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
				continue
			}
			if packet.DebugUDP {
				fmt.Printf("packet: ether %s\n", ether)
				if ip4Frame != nil {
					fmt.Printf("packet: ip4 %s\n", ip4Frame)
				} else {
					fmt.Printf("packet: ip6 %s\n", ip6Frame)
				}
				fmt.Printf("packet: udp %s\n", udp)
			}

			udpSrcPort := udp.SrcPort()
			udpDstPort := udp.DstPort()
			switch {
			case udpDstPort == packet.DHCP4ServerPort || udpDstPort == packet.DHCP4ClientPort: // DHCP4 packet?
				// if udp.DstPort() == packet.DHCP4ServerPort || udp.DstPort() == packet.DHCP4ClientPort {
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
			case udpSrcPort == 53: // DNS response
				// TODO: move this to background goroutine
				dnsEntry, err := h.DNSHandler.DNSProcess(host, ether, udp.Payload())
				if err != nil {
					fmt.Printf("packet: error processing dns: %s\n", err)
					break
				}
				if dnsEntry.Name != "" {
					h.sendDNSNotification(dnsEntry)
				}

			case udpDstPort == 53: // DNS request
			// do nothing

			case udpSrcPort == 5353 || udpDstPort == 5353:
				// Multicast DNS
				if host != nil {
					names, err := h.DNSHandler.ProcessMDNS(host, ether, udp.Payload())
					if err != nil {
						fmt.Printf("packet: error processing mdns: %s\n", err)
						break
					}
					if len(names) > 0 {
						host.MACEntry.Row.Lock()
						if names[0].Name != "" && host.MDNSName != names[0].Name {
							host.MDNSName = names[0].Name
							notify = true
						}
						host.MACEntry.Row.Unlock()
						if packet.Debug && notify {
							fmt.Printf("packet: mdns update name=%s\n", names[0].Name)
						}
					}
				}

			case udpSrcPort == 5252 || udpDstPort == 5252:
				// Link Local Multicast Name Resolution (LLMNR)
				fmt.Printf("proto : LLMNR %s\n", host)
				hosts, err := h.DNSHandler.ProcessMDNS(host, ether, udp.Payload())
				if err != nil {
					fmt.Printf("packet: error processing mdns: %s\n", err)
					break
				}
				for _, v := range hosts {
					fmt.Printf("llmnr : host %+v\n", v)
				}

			case udpSrcPort == 137 || udpDstPort == 137:
				// NBNS
				// do nothing
				fmt.Printf("proto : NBNS %s\n", host)

			case udpSrcPort == 123:
				// Network time synchonization protocol
				// do nothing
				fmt.Printf("proto : NTP %s\n", host)

			case udpSrcPort == 433 || udpDstPort == 433:
				// ssl udp - likely quic?
				// do nothing

			case udpDstPort == 1900:
				// Microsoft Simple Service Discovery Protocol
				if host != nil {
					location, err := h.DNSHandler.ProcessSSDP(host, ether, udp.Payload())
					if err != nil {
						fmt.Printf("packet: error processing ssdp: %s\n", err)
						break
					}
					// Put in queue for service discovery
					if location != "" {
						h.serviceDiscoveryChan <- discoverAction{addr: host.Addr, location: location}
					}
				}

			case udpDstPort == 3702:
				// Web Services Discovery Protocol (WSD)
				fmt.Printf("proto : WSD %s\n", host)

			case udpDstPort == 32412 || udpDstPort == 32414:
				// Plex application multicast on these ports to find players.
				// G'Day Mate (GDM) multicast packets
				// https://github.com/NineWorlds/serenity-android/wiki/Good-Day-Mate
				fmt.Printf("proto : plex %s\n", host)

			default:
				fmt.Printf("proto : warning unexpected udp %s %s\n", udp, host)
			}

		case syscall.ETH_P_ARP: // ARP - 0x0806
			if result, err = h.ARPHandler.ProcessPacket(host, ether, ether.Payload()); err != nil {
				fmt.Printf("packet: error processing arp: %s\n", err)
			}
			if result.Update {
				host, _ = h.session.FindOrCreateHost(result.FrameAddr)
			}

		default:
			fmt.Println("packet: unsupported level 4 header", l4Proto, ether)
		}
		d2 = time.Since(startTime)

		if host != nil {
			h.lockAndSetOnline(host, notify)
		}

		d3 = time.Since(startTime)
		if d3 > time.Microsecond*400 {
			fmt.Printf("packet: warning > 400 microseconds: etherType=%x l4proto=%x l3=%v l4=%v total=%v\n", ether.EtherType(), l4Proto, d1, d2, d3)
		}

		/****
		 ** Uncomment this to help identify deadlocks
		 **
		if packet.Debug {
			fmt.Println("Check engine lock", ether)
			h.session.GlobalLock()
			fmt.Println("Check engine lock pass")
			for _, host := range h.session.HostTable.Table {
				fmt.Println("Check row ", host.Addr)
				host.MACEntry.Row.Lock()
				fmt.Println("Check row lock pass ", host.Addr)
				host.MACEntry.Row.Unlock()
				fmt.Println("Check row unlock pass ", host.Addr)
			}
			fmt.Println("Check engine unlock")
			h.session.GlobalUnlock()
			fmt.Println("Check engine unlock pass ")
		}
		***/
	}
}
