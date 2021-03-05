package dhcp4

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/irai/packet"
	log "github.com/sirupsen/logrus"
)

const configFilename = "./private/dhcp.yaml"

const (
	rebinding uint8 = iota
	selecting
	renewing
	rebooting
)

var (
	mutex sync.Mutex

	// Debug module variable to enable/disable debug & trace messages
	Debug bool
)

// leaseTable is a type to store lease array
type leaseTable [256]Lease

// Mode defines the operational mode: Primary or Secondary server
type Mode int32

const (
	// ModePrimaryServer sets the server to operate as the single DHCP on the LAN
	ModePrimaryServer Mode = iota + 1
	// ModeSecondaryServer sets the server to operate as a secondary DHCP on the LAN; will attack the primary
	ModeSecondaryServer
	// ModeSecondaryServerNice sets the server to operate nice; i.e. will attack captured entries only
	ModeSecondaryServerNice
)

var _ packet.PacketProcessor = &DHCPHandler{}

// DHCPHandler track ongoing leases.
//
type DHCPHandler struct {
	net1         *dhcpSubnet     // home LAN
	net2         *dhcpSubnet     // netfilter LAN
	mode         Mode            // if true, force decline and release packets to homeDHCPServer
	captureTable map[string]bool // Store the subnet for captured mac
	conn         net.PacketConn  // Listen DHCP server port
	conn2        net.PacketConn  // Listen DHCP client port
	notification chan<- Lease
	filename     string
	engine       *packet.Handler
}

func (h *DHCPHandler) Start() error {
	go func() {
		if err := h.clientLoop(context.Background()); err != nil {
			fmt.Println("dhcp4: client loop exited with error=", err)
		}
	}()
	return nil
}

func (h *DHCPHandler) Stop() error                      { return nil }
func (h *DHCPHandler) StartHunt(net.HardwareAddr) error { return nil }
func (h *DHCPHandler) StopHunt(net.HardwareAddr) error  { return nil }

func configChanged(config SubnetConfig, current SubnetConfig) bool {
	if !config.LAN.IP.Equal(current.LAN.IP) ||
		!config.DefaultGW.Equal(current.DefaultGW) ||
		!config.DNSServer.Equal(current.DNSServer) ||
		!config.DHCPServer.Equal(current.DHCPServer) ||
		(config.Duration != 0 && config.Duration != current.Duration) ||
		(config.FirstIP != nil && !config.FirstIP.Equal(current.FirstIP)) ||
		(config.LastIP != nil && !config.LastIP.Equal(current.LastIP)) {
		log.Infof("dhcp4: config parameters changed  config=%+v", config)
		log.Infof("dhcp4: config parameters changed current=%+v", current)
		return true
	}
	return false
}

// Attach return a dhcp handler with two internal subnets.
// func New(home SubnetConfig, netfilter SubnetConfig, filename string) (handler *DHCPHandler, err error) {
func Attach(engine *packet.Handler, home SubnetConfig, netfilter SubnetConfig, filename string) (handler *DHCPHandler, err error) {

	handler = &DHCPHandler{}
	handler.captureTable = make(map[string]bool)
	handler.filename = filename
	handler.mode = ModeSecondaryServer

	// Reset leases if error or config has changed
	handler.net1, handler.net2, err = loadConfig(handler.filename)
	if err != nil || handler.net1 == nil || handler.net2 == nil ||
		configChanged(home, handler.net1.SubnetConfig) || configChanged(netfilter, handler.net2.SubnetConfig) {
		log.Error("dhcp4: config file reset ", err)

		// net1 is home LAN
		handler.net1, err = newSubnet(home)
		if err != nil {
			return nil, fmt.Errorf("home config : %w", err)
		}

		// net2 is netfilter LAN
		handler.net2, err = newSubnet(netfilter)
		if err != nil {
			return nil, fmt.Errorf("netfilter config : %w", err)
		}
	}

	// Add static and classless route options
	handler.net2.appendRouteOptions(handler.net1.DefaultGW, handler.net1.LAN.Mask, handler.net2.DefaultGW)

	if debugging() {
		handler.net1.printSubnet()
	}

	// Free any expired lease and set the capture table for any lease in subnet 2
	handler.net1.freeEntries()
	handler.net2.freeEntries()

	if debugging() {
		log.WithFields(log.Fields{"netfilterLAN": handler.net2.LAN.String(), "netfilterGW": handler.net2.DefaultGW, "firstIP": handler.net2.FirstIP,
			"lastIP": handler.net2.LastIP}).Debug("dhcp4: Server Config")
	}

	handler.engine = engine
	engine.HandlerDHCP4 = handler
	return handler, nil
}

func (h *DHCPHandler) Detach() error {
	h.engine.Lock()
	defer h.engine.Unlock()
	h.engine.HandlerDHCP4 = packet.PacketNOOP{}
	return nil
}

// Mode return the disrupt flag
// if true we are sending fake decline, release and discover packets
func (h *DHCPHandler) Mode() Mode {
	return h.mode
}

// SetMode set to true to disrupt the home lan server
// with fake decline, release and discover packets
func (h *DHCPHandler) SetMode(mode Mode) {
	h.mode = mode
}

// PrintTable is a helper function to print the table to stdout
func (h *DHCPHandler) PrintTable() {
	h.net1.printSubnet()
	h.net2.printSubnet()
}

// Leases return all DHCP leases
func (h *DHCPHandler) Leases() []Lease {
	l := h.net1.getLeases()
	l = append(l, h.net2.getLeases()...)
	return l
}

// AddNotificationChannel set the notification channel
func (h *DHCPHandler) AddNotificationChannel(channel chan<- Lease) {
	h.notification = channel
}

// Capture will start the process to capture the client MAC
func (h *DHCPHandler) Capture(mac net.HardwareAddr) {

	mutex.Lock()
	defer mutex.Unlock()

	// do nothing if already captured
	if h.isCapturedLocked(mac) != nil {
		return
	}

	log.WithFields(log.Fields{"mac": mac}).Info("dhcp4: start capture")

	// Add to list of macs being captured
	h.captureTable[string(mac)] = true

	// Delete lease in net1 if it exist
	if e := h.net1.findMAC(mac); e != nil {
		freeLease(e)
	}

	if h.mode == ModeSecondaryServer || h.mode == ModeSecondaryServerNice {
		// Fake a dhcp release so router will force the client to discover when it attempts to reconnect
		if lease := h.net1.findMAC(mac); lease != nil {
			log.WithFields(log.Fields{"clientID": lease.ClientID, "mac": mac, "ip": lease.IP}).Info("dhcp4: client - send release to server")
			h.forceRelease(lease.ClientID, h.net1.DefaultGW, mac, lease.IP, nil)
		}
	}
}

// Release will end the capture process
func (h *DHCPHandler) Release(mac net.HardwareAddr) {
	log.WithFields(log.Fields{"mac": mac}).Info("dhcp4: end capture")

	mutex.Lock()
	defer mutex.Unlock()

	// delete from list of macs being captured
	delete(h.captureTable, string(mac))
	if e := h.net2.findMAC(mac); e != nil {
		freeLease(e)
	}
}

// IsCaptured returns true if mac and ip are valid DHCP entry in the capture state.
// Otherwise returns false.
func (h *DHCPHandler) IsCaptured(mac net.HardwareAddr) net.IP {
	mutex.Lock()
	defer mutex.Unlock()

	return h.isCapturedLocked(mac)
}

func (h *DHCPHandler) isCapturedLocked(mac net.HardwareAddr) net.IP {

	if _, ok := h.captureTable[string(mac)]; !ok {
		return nil
	}

	lease := h.net2.findMAC(mac)
	if lease == nil {
		if debugging() {
			log.WithFields(log.Fields{"mac": mac}).Debug("dhcp4: mac not captured - not in dhcp table")
		}
		return nil
	}
	if lease.State != StateAllocated {
		if debugging() {
			log.WithFields(log.Fields{"mac": mac, "state": lease.State}).Debugf("dhcp4: mac not captured")
		}
		return nil
	}
	return lease.IP
}
