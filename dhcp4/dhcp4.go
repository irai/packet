// Package dhcp4 implements a dhcp server designed to operate as a secondary
// dhcp server on the same lan.
//
// Initial implementation inspired by code written by http://richard.warburton.it/
// see: https://github.com/krolaw/dhcp4
package dhcp4

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
)

// Debug enable/disable debug messages
var Debug bool

const module = "dhcp4"

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

type DHCP4Handler interface {
	// Start() error
	Close() error
	ProcessPacket(packet.Frame) error
	StartHunt(packet.Addr) error
	StopHunt(packet.Addr) error
	// CheckAddr(packet.Addr) error
	MinuteTicker(time.Time) error
}

// PacketNOOP is a no op packet processor
type PacketNOOP struct{}

var _ DHCP4Handler = PacketNOOP{}

// func (p PacketNOOP) Start() error                     { return nil }
func (p PacketNOOP) ProcessPacket(packet.Frame) error { return nil }
func (p PacketNOOP) StartHunt(addr packet.Addr) error { return nil }
func (p PacketNOOP) StopHunt(addr packet.Addr) error  { return nil }
func (p PacketNOOP) Close() error                     { return nil }
func (p PacketNOOP) MinuteTicker(now time.Time) error { return nil }

var _ DHCP4Handler = &Handler{}
var LeaseFilename = "./dhcpleases.yaml"

type leaseTable map[string]*Lease

// Handler is the main dhcp4 handler
type Handler struct {
	session   *packet.Session // engine handler
	mode      Mode            // operating mode: primary, secondary, nice
	filename  string          // leases filename
	closed    bool            // indicates that Close() function was called
	closeChan chan bool       // channel to close underlying goroutines
	table     leaseTable      // in memory lease table
	net1      *dhcpSubnet     // home LAN
	net2      *dhcpSubnet     // netfilter LAN - a subnet of net1
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

	// validate dns server : default to router if not given
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
		// LastIP:     net.ParseIP("192.168.0.127"),
	}
	// Segment network - netfilter subnet includes netfilter subnet only
	netfilterSubnet := SubnetConfig{
		// LAN:        netip.PrefixFrom({IP: config.NetfilterIP.IP.Mask(config.NetfilterIP.Mask), Mask: config.NetfilterIP.Mask},
		LAN:        config.NetfilterIP.Masked(),
		DefaultGW:  config.NetfilterIP.Addr(),
		DHCPServer: session.NICInfo.HostAddr4.IP,
		DNSServer:  packet.DNSv4CloudFlareFamily1,
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
	h.net1.ID = "net1"
	h.net2.ID = "net2"

	// Add static and classless route options
	h.net2.appendRouteOptions(h.net1.DefaultGW, net.CIDRMask(h.net1.LAN.Bits(), 32-h.net1.LAN.Bits()), h.net2.DefaultGW)
	h.saveConfig(h.filename)
	return h, nil
}

/**
// Start implements PacketProcessor interface
func (h *Handler) Start() error {
	h.closed = false
	h.closeChan = make(chan bool) // goroutines listen on this for closure
	return nil
}
***/

// Stop implements PacketProcessor interface
func (h *Handler) Close() error {
	if h.closed {
		return nil
	}
	h.closed = true
	close(h.closeChan)
	return nil
}

// MinuteTicker implements packet processor interface
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
		fmt.Printf("dhcp4: config parameters changed new config=%+v\n", config)
		fmt.Printf("dhcp4: config parameters changed old config=%+v\n", current)
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
	}
	return nil
}

// StopHunt will end the capture process
func (h *Handler) StopHunt(addr packet.Addr) error {
	if Debug {
		fmt.Printf("dhcp4: stop hunt %s\n", addr)
	}
	return nil
}

/***
// HuntStage returns StageHunt if mac and ip are valid DHCP entry in the capture state.
// Otherwise returns false.
func (h *Handler) CheckAddr(addr packet.Addr) error {
	h.Lock()
	defer h.Unlock()

	lease := h.findByIP(addr.IP)

	if lease != nil && lease.State == StateAllocated {
		return nil
	}
	fastlog.NewLine(module, "failed to get dhcp hunt status").Struct(addr).Error(packet.ErrNotFound).Write()
	return packet.ErrNotFound
}
***/

// ProcessPacket implements PacketProcessor interface
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
		if Debug {
			fastlog.NewLine(module, "dhcp client packet").Struct(dhcpFrame).Write()
		}
		err := h.processClientPacket(frame.Host, dhcpFrame)
		return err
	}

	if Debug {
		fastlog.NewLine(module, "process packet").Label("src").Struct(frame.SrcAddr).Label("dst").Struct(frame.DstAddr).Struct(dhcpFrame).Write()
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
		fmt.Printf("dhcp4: message type not supported %v", reqType)
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
		if Debug {
			fastlog.NewLine(module, "send reply to").Struct(dstAddr).Struct(response).Write()
		}
		srcAddr := packet.Addr{MAC: h.session.NICInfo.HostAddr4.MAC, IP: h.session.NICInfo.HostAddr4.IP, Port: DHCP4ServerPort}
		if err := sendDHCP4Packet(h.session.Conn, srcAddr, dstAddr, response); err != nil {
			fmt.Printf("dhcp4: failed sending packet error=%s", err)
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
