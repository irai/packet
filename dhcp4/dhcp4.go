// Package dhcp4 implements a dhcp server designed to operate as a secondary
// dhcp server on the same lan.
//
// It allows the segmentation of the LAN into two distintict subnets, one used for
// hosts not captured, and a more confined subnet for hosts in capture state.
//
// Captured hosts will have a specific subnet with the default router set to us so that
// all captured host traffic is directed to us.
//
// It may also be set to attack the primary DHCP host to exhaust entries.
//
// The original implementation used Richard Burton's dhcp4 package
// (see: https://github.com/krolaw/dhcp4) for processing of dhcp packets but current versions
// use our own packet package.
package dhcp4

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/irai/packet/fastlog"

	"github.com/irai/packet"
)

const module = "dhcp4"

var Logger = fastlog.New(module)
var LeaseFilename = "./dhcpleases.yaml"

type Mode int32

// Mode type for operational mode: Primary or Secondary server
const (
	ModePrimaryServer       Mode = iota + 1 // sets the server to operate as the single DHCP on the LAN
	ModeSecondaryServer                     // sets the server to operate as a secondary DHCP on the LAN; will attack the primary
	ModeSecondaryServerNice                 // sets the server to operate nice; i.e. will attack captured entries only
)

const (
	rebinding uint8 = iota
	selecting
	renewing
	rebooting
)

// Config contains configuration overrides
type Config struct {
	// ClientConn    net.PacketConn
	Mode          Mode
	NetfilterIP   netip.Prefix
	DNSServer     netip.Addr
	LeaseFilename string
}

// Handler is the main dhcp4 handler
type Handler struct {
	session   *packet.Session   // engine handler
	mode      Mode              // operating mode: primary, secondary, nice
	filename  string            // leases filename
	closed    bool              // indicates that Close() function was called
	closeChan chan bool         // channel to close underlying goroutines
	table     map[string]*Lease // in memory lease table
	net1      *dhcpSubnet       // home LAN
	net2      *dhcpSubnet       // netfilter LAN - a subnet of net1
	sync.Mutex
}

// New returns a dhcp handler.
func New(session *packet.Session) (handler *Handler, err error) {
	config := Config{Mode: ModeSecondaryServer, DNSServer: session.NICInfo.RouterAddr4.IP, LeaseFilename: LeaseFilename}
	return config.New(session)
}

// New accepts a configuration structure and return a dhcp handler with two internal subnets.
func (config Config) New(session *packet.Session) (h *Handler, err error) {
	h = &Handler{table: map[string]*Lease{}}
	h.session = session
	h.filename = config.LeaseFilename
	h.closeChan = make(chan bool)

	if Logger.IsDebug() {
		Logger.Msg("new dhcp4 handler").Sprintf("config", config).Write()
	}

	// validate netfilter subnet
	if !config.NetfilterIP.Addr().IsValid() {
		config.NetfilterIP = netip.PrefixFrom(session.NICInfo.HostAddr4.IP, session.NICInfo.HomeLAN4.Bits()) // using single subnet: same as home subnet
	}
	if !session.NICInfo.HomeLAN4.Contains(config.NetfilterIP.Addr()) {
		return nil, fmt.Errorf("netfilter ip=%s does not exist in home net=%s: %w", config.NetfilterIP, session.NICInfo.HomeLAN4, packet.ErrInvalidIP)
	}

	// validate mode - default to SecondaryServerNice
	if config.Mode != ModePrimaryServer && config.Mode != ModeSecondaryServer && config.Mode != ModeSecondaryServerNice {
		config.Mode = ModeSecondaryServerNice
	}
	h.mode = config.Mode

	// validate dns server : set default to router IP
	if !config.DNSServer.IsValid() {
		config.DNSServer = session.NICInfo.RouterAddr4.IP
	}

	// Segment network - home subnet includes the whole home LAN
	homeSubnet := SubnetConfig{
		LAN:        session.NICInfo.HomeLAN4,
		DefaultGW:  session.NICInfo.RouterAddr4.IP,
		DHCPServer: session.NICInfo.HostAddr4.IP,
		DNSServer:  config.DNSServer,
		Stage:      packet.StageNormal,
		// FirstIP:    net.ParseIP("192.168.0.10"),
	}
	// Segment network - netfilter subnet includes netfilter subnet only
	netfilterSubnet := SubnetConfig{
		LAN:        config.NetfilterIP.Masked(),
		DefaultGW:  config.NetfilterIP.Addr(),
		DHCPServer: session.NICInfo.HostAddr4.IP,
		DNSServer:  packet.DNSv4CloudFlareFamily1,
		Stage:      packet.StageRedirected,
		// FirstIP:    net.ParseIP("192.168.0.10"),
	}

	// Reset leases if error or config has changed
	h.net1, h.net2, h.table, err = h.loadConfig(h.filename)
	if err != nil || h.net1 == nil || h.net2 == nil || h.table == nil ||
		configChanged(homeSubnet, h.net1.SubnetConfig) || configChanged(netfilterSubnet, h.net2.SubnetConfig) {

		if err != nil && !os.IsNotExist(err) {
			Logger.Msg("invalid config file. resetting...").String("filename", h.filename).Write()
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
	h.net1.ID = "net1"
	h.net2.ID = "net2"

	// Add static and classless route options
	h.net2.appendRouteOptions(h.net1.DefaultGW, net.CIDRMask(h.net1.LAN.Bits(), 32-h.net1.LAN.Bits()), h.net2.DefaultGW)
	h.saveConfig(h.filename)
	if Logger.IsInfo() {
		Logger.Msg("subnet 1").Sprintf("config", h.net1).Write()
		Logger.Msg("subnet 2").Sprintf("config", h.net2).Write()
	}
	return h, nil
}

// Close free up internal resouces.
func (h *Handler) Close() error {
	if h.closed {
		return nil
	}
	h.closed = true
	close(h.closeChan)
	return nil
}

// MinuteTicker perform checks and free leases as required.
func (h *Handler) MinuteTicker(now time.Time) error {
	h.Lock()
	defer h.Unlock()
	h.freeLeases(now)
	return nil
}

func configChanged(config SubnetConfig, current SubnetConfig) bool {
	if config.LAN.Addr() != current.LAN.Addr() ||
		config.DefaultGW != current.DefaultGW ||
		config.DNSServer != current.DNSServer ||
		config.DHCPServer != current.DHCPServer ||
		(config.Duration != 0 && config.Duration != current.Duration) ||
		(config.FirstIP.Is4() && config.FirstIP != current.FirstIP) {
		Logger.Msg("config parameters changed").Sprintf("new config=%+v", config).Write()
		Logger.Msg("config parameters changed").Sprintf("old config=%+v", current).Write()
		return true
	}
	return false
}

// Mode returns the current mode
func (h *Handler) Mode() Mode {
	return h.mode
}

// SetMode changes the operating mode
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

// StartHunt will start the process to capture the client DHCP negotiation
func (h *Handler) StartHunt(addr packet.Addr) error {
	if Logger.IsInfo() {
		Logger.Msg("start hunt").Struct(addr).Write()
	}

	h.Lock() // local handler lock
	defer h.Unlock()

	if lease := h.findByIP(addr.IP); lease != nil && lease.subnet.Stage != packet.StageRedirected {
		// Fake a dhcp release so router will force the client to discover when it attempts to reconnect
		if h.mode == ModeSecondaryServer || h.mode == ModeSecondaryServerNice {
			h.forceRelease(lease.ClientID, h.net1.DefaultGW, lease.Addr.MAC, lease.Addr.IP, nil)
		}
	}
	return nil
}

// StopHunt will end the capture process
func (h *Handler) StopHunt(addr packet.Addr) error {
	if Logger.IsInfo() {
		Logger.Msg("stop hunt").Struct(addr).Write()
	}
	return nil
}

// ProcessPacket handles a DHCP4 packet performing DHCP4 spoofing and
// segmentation to keep captured hosts on a different subnet.
func (h *Handler) ProcessPacket(frame packet.Frame) error {
	if frame.PayloadID != packet.PayloadDHCP4 {
		return packet.ErrParseProtocol
	}
	dhcpFrame := DHCP4(frame.Payload())
	if err := dhcpFrame.IsValid(); err != nil {
		return err
	}

	// if udp.DstPort() == DHCP4ClientPort {
	if frame.DstAddr.Port == DHCP4ClientPort {
		if Logger.IsInfo() {
			Logger.Msg("dhcp client packet").Struct(dhcpFrame).Write()
		}
		err := h.processClientPacket(frame.Host, dhcpFrame)
		return err
	}

	if Logger.IsDebug() {
		Logger.Msg("process packet").Label("src").Struct(frame.SrcAddr).Label("dst").Struct(frame.DstAddr).Struct(dhcpFrame).Write()
	}

	options := dhcpFrame.ParseOptions()
	var reqType MessageType
	if t := options[OptionDHCPMessageType]; len(t) != 1 {
		fmt.Println("dhcp4 : skiping dhcp - missing message type")
		return packet.ErrParseFrame
	} else {
		reqType = MessageType(t[0])
		if reqType < Discover || reqType > Inform {
			fmt.Println("dhcp4 : skiping dhcp packet invalid type ", reqType)
			return packet.ErrParseFrame
		}
	}

	var response DHCP4

	h.Lock()
	switch reqType {
	case Discover:
		response = h.handleDiscover(dhcpFrame, options)
	case Request:
		response = h.handleRequest(frame.Host, dhcpFrame, options, frame.SrcAddr.IP)
	case Decline:
		response = h.handleDecline(dhcpFrame, options)
	case Release:
		response = h.handleRelease(dhcpFrame, options)
	case Offer:
		fmt.Println("dhcp4: error got dhcp offer")
	default:
		Logger.Msg("message not supported").Uint8("type", uint8(reqType)).Write()
	}
	h.Unlock()

	if response != nil {
		var dstAddr packet.Addr
		// If IP not available, broadcast
		if frame.SrcAddr.IP == packet.IPv4zero || dhcpFrame.Broadcast() {
			dstAddr = packet.Addr{MAC: packet.EthBroadcast, IP: packet.IPv4bcast, Port: DHCP4ClientPort}
		} else {
			dstAddr = packet.Addr{MAC: frame.SrcAddr.MAC, IP: frame.SrcAddr.IP, Port: DHCP4ClientPort}
		}
		if Logger.IsDebug() {
			Logger.Msg("send reply to").Struct(dstAddr).Struct(response).Write()
		}
		srcAddr := packet.Addr{MAC: h.session.NICInfo.HostAddr4.MAC, IP: h.session.NICInfo.HostAddr4.IP, Port: DHCP4ServerPort}
		if err := sendDHCP4Packet(h.session.Conn, srcAddr, dstAddr, response); err != nil {
			Logger.Msg("send packet failed").Error(err).Write()
			return err
		}
	}
	return nil
}

func getClientID(p DHCP4, options Options) []byte {
	clientID, ok := options[OptionClientIdentifier]
	if !ok {
		clientID = p.CHAddr()
	}
	return clientID
}
