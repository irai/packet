package dhcp4

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/irai/packet"
)

const (
	rebinding uint8 = iota
	selecting
	renewing
	rebooting
)

var (
	// Debug module variable to enable/disable debug & trace messages
	Debug bool
)

// Mode type for operational mode: Primary or Secondary server
type Mode int32

const (
	// ModePrimaryServer sets the server to operate as the single DHCP on the LAN
	ModePrimaryServer Mode = iota + 1
	// ModeSecondaryServer sets the server to operate as a secondary DHCP on the LAN; will attack the primary
	ModeSecondaryServer
	// ModeSecondaryServerNice sets the server to operate nice; i.e. will attack captured entries only
	ModeSecondaryServerNice
)

// Config contains configuration overrides
type Config struct {
	ClientConn net.PacketConn
}

type DHCP4Handler interface {
	packet.PacketProcessor
}

var _ DHCP4Handler = &Handler{}

// Start implements PacketProcessor interface
func (h *Handler) Start() error {
	return nil
}

// Stop implements PacketProcessor interface
func (h *Handler) Stop() error { return nil }

// MinuteTicker implements packet processor interface
func (h *Handler) MinuteTicker(now time.Time) error {
	h.Lock()
	defer h.Unlock()
	h.freeLeases(now)
	return nil
}

func configChanged(config SubnetConfig, current SubnetConfig) bool {
	if !config.LAN.IP.Equal(current.LAN.IP) ||
		!config.DefaultGW.Equal(current.DefaultGW) ||
		!config.DNSServer.Equal(current.DNSServer) ||
		!config.DHCPServer.Equal(current.DHCPServer) ||
		(config.Duration != 0 && config.Duration != current.Duration) ||
		(config.FirstIP != nil && !config.FirstIP.Equal(current.FirstIP)) ||
		(config.LastIP != nil && !config.LastIP.Equal(current.LastIP)) {
		fmt.Printf("dhcp4: config parameters changed  config=%+v", config)
		fmt.Printf("dhcp4: config parameters changed current=%+v", current)
		return true
	}
	return false
}

// Handler is the main dhcp4 handler
type Handler struct {
	session *packet.Session // engine handler
	// clientConn net.PacketConn  // Listen DHCP client port
	mode      Mode        // if true, force decline and release packets to homeDHCPServer
	filename  string      // leases filename
	closed    bool        // indicates that detach function was called
	closeChan chan bool   // channel to close underlying goroutines
	table     leaseTable  // lease table
	net1      *dhcpSubnet // home LAN
	net2      *dhcpSubnet // netfilter LAN
	sync.Mutex
}

// New return a dhcp handler with two internal subnets.
// func New(home SubnetConfig, netfilter SubnetConfig, filename string) (handler *DHCPHandler, err error) {
func New(session *packet.Session, netfilterIP net.IPNet, dnsServer net.IP, filename string) (handler *Handler, err error) {
	return Config{}.New(session, netfilterIP, dnsServer, filename)
}

// New accepts a configuration structure and return a dhcp handler
func (config Config) New(session *packet.Session, netfilterIP net.IPNet, dnsServer net.IP, filename string) (h *Handler, err error) {

	// validate networks
	if !session.NICInfo.HomeLAN4.Contains(netfilterIP.IP) || netfilterIP.Contains(session.NICInfo.HomeLAN4.IP) {
		return nil, packet.ErrInvalidIP
	}

	h = &Handler{table: map[string]*Lease{}}
	// handler.captureTable = make(map[string]bool)
	h.filename = filename
	h.mode = ModeSecondaryServerNice
	h.closeChan = make(chan bool) // goroutines listen on this for closure

	if dnsServer == nil {
		dnsServer = session.NICInfo.RouterIP4.IP
	}
	// Segment network
	homeSubnet := SubnetConfig{
		LAN:        session.NICInfo.HomeLAN4,
		DefaultGW:  session.NICInfo.RouterIP4.IP.To4(),
		DHCPServer: session.NICInfo.HostIP4.IP.To4(),
		DNSServer:  dnsServer.To4(),
		Stage:      packet.StageNormal,
		// FirstIP:    net.ParseIP("192.168.0.10"),
		// LastIP:     net.ParseIP("192.168.0.127"),
	}
	netfilterSubnet := SubnetConfig{
		LAN:        net.IPNet{IP: netfilterIP.IP.Mask(netfilterIP.Mask), Mask: netfilterIP.Mask},
		DefaultGW:  netfilterIP.IP.To4(),
		DHCPServer: session.NICInfo.HostIP4.IP,
		DNSServer:  packet.CloudFlareFamilyDNS1,
		Stage:      packet.StageRedirected,
		// FirstIP:    net.ParseIP("192.168.0.10"),
		// LastIP:     net.ParseIP("192.168.0.127"),
	}

	// Reset leases if error or config has changed
	h.net1, h.net2, h.table, err = loadConfig(h.filename)
	if err != nil || h.net1 == nil || h.net2 == nil || h.table == nil ||
		configChanged(homeSubnet, h.net1.SubnetConfig) || configChanged(netfilterSubnet, h.net2.SubnetConfig) {
		if err != nil && !os.IsNotExist(err) {
			fmt.Printf("dhcp4: invalid config file=%s. resetting...\n", h.filename)
		}
		h.table = make(map[string]*Lease)

		// net1 is home LAN
		h.net1, err = newSubnet(homeSubnet)
		if err != nil {
			return nil, fmt.Errorf("home config : %w", err)
		}

		// net2 is netfilter LAN
		h.net2, err = newSubnet(netfilterSubnet)
		if err != nil {
			return nil, fmt.Errorf("netfilter config : %w", err)
		}
	}

	// Add static and classless route options
	h.net2.appendRouteOptions(h.net1.DefaultGW, h.net1.LAN.Mask, h.net2.DefaultGW)

	// if Debug {
	// log.WithFields(log.Fields{"netfilterLAN": h.net2.LAN.String(), "netfilterGW": h.net2.DefaultGW, "firstIP": h.net2.FirstIP,
	// "lastIP": h.net2.LastIP}).Debug("dhcp4: Server Config")
	// }

	h.session = session
	// session.HandlerDHCP4 = h

	h.saveConfig(h.filename)
	return h, nil
}

// Detach implements the PacketProcessor interface
func (h *Handler) Close() error {
	h.closed = true
	close(h.closeChan)
	return nil
}

// Mode return the disrupt flag
// if true we are sending fake decline, release and discover packets
func (h *Handler) Mode() Mode {
	return h.mode
}

// SetMode set to true to disrupt the home lan server
// with fake decline, release and discover packets
func (h *Handler) SetMode(mode Mode) {
	h.mode = mode
}

// PrintTable is a helper function to print the table to stdout
func (h *Handler) PrintTable() {
	h.Lock()
	defer h.Unlock()
	h.printTable()
}

func (h *Handler) printTable() {
	for _, v := range h.table {
		fmt.Printf("dhcp4 : %v\n", v)
	}
}

// StartHunt will start the process to capture the client MAC
func (h *Handler) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Debug {
		fmt.Printf("dhcp4: start hunt %s\n", addr)
	}

	h.Lock() // local handler lock
	defer h.Unlock()

	if lease := h.findByIP(addr.IP); lease != nil && lease.subnet.Stage != packet.StageRedirected {
		// Fake a dhcp release so router will force the client to discover when it attempts to reconnect
		if h.mode == ModeSecondaryServer || h.mode == ModeSecondaryServerNice {
			h.forceRelease(lease.ClientID, h.net1.DefaultGW, lease.Addr.MAC, lease.Addr.IP, nil)
		}
		// h.engine.SetIP4Offer(host, net.IPv4zero)
	}
	return packet.StageHunt, nil
}

// StopHunt will end the capture process
func (h *Handler) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	if Debug {
		fmt.Printf("dhcp4: stop hunt %s\n", addr)
	}
	return h.CheckAddr(addr)
}

// HuntStage returns StageHunt if mac and ip are valid DHCP entry in the capture state.
// Otherwise returns false.
func (h *Handler) CheckAddr(addr packet.Addr) (packet.HuntStage, error) {
	h.Lock()
	defer h.Unlock()

	lease := h.findByIP(addr.IP)

	if lease != nil && lease.State == StateAllocated {
		return lease.subnet.Stage, nil
	}
	return packet.StageNormal, packet.ErrNotFound
}

// ProcessPacket implements PacketProcessor interface
func (h *Handler) ProcessPacket(host *packet.Host, b []byte, header []byte) (packet.Result, error) {
	ether := packet.Ether(b)
	ip4 := packet.IP4(ether.Payload())
	if !ip4.IsValid() {
		return packet.Result{}, packet.ErrInvalidIP
	}
	udp := packet.UDP(ip4.Payload())
	if !udp.IsValid() || len(udp.Payload()) < 240 {
		return packet.Result{}, packet.ErrInvalidIP
	}

	dhcpFrame := DHCP4(udp.Payload())
	if !dhcpFrame.IsValid() {
		return packet.Result{}, packet.ErrParseFrame
	}
	if Debug {
		fmt.Printf("dhcp4 : ether %s\n", ether)
		fmt.Printf("dhcp4 : ip4 %s\n", ip4)
		fmt.Printf("dhcp4 : udp %s\n", udp)
		fmt.Printf("dhcp4 : dhcp %s\n", dhcpFrame)
	}

	if udp.DstPort() == packet.DHCP4ClientPort {
		err := h.processClientPacket(host, dhcpFrame)
		return packet.Result{}, err
	}

	options := dhcpFrame.ParseOptions()
	var reqType MessageType
	if t := options[OptionDHCPMessageType]; len(t) != 1 {
		fmt.Println("dhcp4 : skiping dhcp packet with len not 1")
		return packet.Result{}, packet.ErrParseFrame
	} else {
		reqType = MessageType(t[0])
		if reqType < Discover || reqType > Inform {
			fmt.Println("dhcp4 : skiping dhcp packet invalid type ", reqType)
			return packet.Result{}, packet.ErrParseFrame
		}
	}

	// retrieve the sender IP address
	// ipStr , portStr, err := net.SplitHostPort(addr.String())

	// if res := h.processDHCP(req, reqType, options, ip4.Src()); res != nil {
	var response DHCP4
	var result packet.Result

	h.Lock()

	switch reqType {
	case Discover:
		result, response = h.handleDiscover(dhcpFrame, options)

	case Request:
		result, response = h.handleRequest(host, dhcpFrame, options, ip4.Src())

	case Decline:
		response = h.handleDecline(dhcpFrame, options)

	case Release:
		response = h.handleRelease(dhcpFrame, options)

	case Offer:
		fmt.Println("dhcp4: error got dhcp offer")

	default:
		fmt.Printf("dhcp4: message type not supported %v", reqType)
	}

	h.Unlock()

	if response != nil {
		// If IP not available, broadcast

		var dstAddr packet.Addr
		if ip4.Src().Equal(net.IPv4zero) || dhcpFrame.Broadcast() {
			dstAddr = packet.Addr{MAC: packet.EthBroadcast, IP: net.IPv4bcast, Port: packet.DHCP4ClientPort}
		} else {
			dstAddr = packet.Addr{MAC: ether.Src(), IP: ip4.Src(), Port: packet.DHCP4ClientPort}
		}

		if Debug {
			fmt.Println("dhcp4 : send reply to ", dstAddr, response)
		}

		srcAddr := packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.HostIP4.IP, Port: packet.DHCP4ServerPort}
		if err := h.sendDHCP4Packet(srcAddr, dstAddr, response); err != nil {
			fmt.Printf("dhcp4: failed sending packet error=%s", err)
			return packet.Result{}, err
		}
	}
	return result, nil
}

func getClientID(p DHCP4, options Options) []byte {
	clientID, ok := options[OptionClientIdentifier]
	if !ok {
		clientID = p.CHAddr()
	}
	return clientID
}
