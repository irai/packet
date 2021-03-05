package dhcp4

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

const (
	// StateFree indicates the lease is free for reuse
	StateFree = "free"

	// StateDiscovery indicates the lease is in discovery state
	StateDiscovery = "discovery"

	// StateAllocated indicates the lease is allocated
	StateAllocated = "allocated"

	// StateReserved indicates the lease is reserved
	StateReserved = "reserved"
)

// Lease stores a lease lease
//
// Concurrency: not safe
//    There race conditions for all functions in this file.
//    You need to use a mutext before calling these if they are likely called by multiple goroutines.
type Lease struct {
	State      string
	ClientID   []byte
	XID        []byte `yaml:"-"`
	Count      int    `yaml:"-"` // a counter to check for repeat packets
	Name       string
	MAC        net.HardwareAddr
	IP         net.IP
	DHCPExpiry time.Time
}

// SubnetConfig hold configuration values for the subnet
//
// DefaultGW must be accessible in the subnet
// example: lan 192.168.0.0/24, gw 192.168.0.1
//          lan 192.168.0.128/25, gw 192.168.0.129
type SubnetConfig struct {
	LAN        net.IPNet     // lan address & netmask
	DefaultGW  net.IP        // Default Gateway for subnet
	DHCPServer net.IP        // DHCP server ID
	DNSServer  net.IP        // DNS server IP
	FirstIP    net.IP        // First IP in range
	LastIP     net.IP        // Last IP in range
	Duration   time.Duration // lease duration
}

// dhcpSubnet hold the 256 lease array for subnet
// We use the last byte in IPv4 as the index.
type dhcpSubnet struct {
	SubnetConfig            // anonymous struct
	broadcast    net.IP     // hold the net broadcast IP
	options      Options    // Options to send to DHCP Clients
	leases       leaseTable // Array to keep track of leases
	nextIP       uint
}

// newSubnet create a subnet structure to track lease allocation.
func newSubnet(config SubnetConfig) (*dhcpSubnet, error) {

	config.LAN.IP = config.LAN.IP.Mask(config.LAN.Mask) // ensure this is a network address

	var subnet dhcpSubnet
	subnet.LAN = net.IPNet{IP: config.LAN.IP.Mask(config.LAN.Mask).To4(), Mask: config.LAN.Mask}

	// get broadcast addr
	subnet.broadcast = dupIP(subnet.LAN.IP).To4()
	for i := range subnet.broadcast {
		subnet.broadcast[i] = subnet.broadcast[i] | ^subnet.LAN.Mask[i]
	}

	// default values for first and last IPs
	config.FirstIP = config.FirstIP.To4()
	if config.FirstIP == nil || config.FirstIP.Equal(net.IPv4zero) || config.FirstIP[3] < subnet.LAN.IP[3] {
		config.FirstIP = subnet.LAN.IP
	}
	config.LastIP = config.LastIP.To4()
	if config.LastIP == nil || config.LastIP.Equal(net.IPv4zero) || config.LastIP[3] > subnet.broadcast[3] {
		config.LastIP = subnet.broadcast
	}
	subnet.Duration = config.Duration
	if subnet.Duration == 0 {
		subnet.Duration = 4 * time.Hour
	}

	// convert all to IPv4
	subnet.DHCPServer = config.DHCPServer.To4()
	subnet.DefaultGW = config.DefaultGW.To4()
	subnet.FirstIP = config.FirstIP.To4()
	subnet.LastIP = config.LastIP.To4()
	subnet.DNSServer = config.DNSServer.To4()

	if !config.LAN.Contains(config.DefaultGW) {
		return nil, fmt.Errorf("DefaultGW not in subnet")
	}
	if !config.LAN.Contains(config.FirstIP) {
		return nil, fmt.Errorf("FirstIP not in subnet")
	}
	if !config.LAN.Contains(config.LastIP) {
		return nil, fmt.Errorf("LastIP not in subnet")
	}
	if subnet.FirstIP[3] >= subnet.LastIP[3] {
		return nil, fmt.Errorf("firstIP after lastIP IPs")
	}
	if subnet.DNSServer.IsUnspecified() {
		return nil, fmt.Errorf("invalid DNSServer")
	}

	subnet.nextIP = uint(subnet.FirstIP[3])

	if debugging() {
		log.Tracef("dhcp4: createSubnet %+v", config)
	}

	// Init the lease table
	now := time.Now()
	for i := range subnet.leases {
		subnet.leases[i].State = StateFree
		subnet.leases[i].IP = net.IPv4zero
		subnet.leases[i].DHCPExpiry = now
	}

	// Common options request:
	//   [1 121 3 6 15 119 252] - iphone
	//   [1 3 6 15 31 33 43 44 46 47 119 121 249 252] - Dell Win 10
	//   [1 15 3 6 44 46 47 31 33 121 249 252 43] - Win phone
	//   [1 33 3 6 15 26 28 51 58 59] - Android
	// 1-subnet mask; 3-router; 6-DNS; 15-domain name;26-MTU; 28-Broadcast addr; 31-router discovery;33-static route;
	// 43-Vendor specific;44-Netbios name; 47-Netbios scope;51-Lease time;58-Renewal time (t1); 59-rebind time(t2)
	// 121-classless route option(takes precedence to 33)
	subnet.options = Options{
		OptionSubnetMask:       []byte(subnet.LAN.Mask), // must be before router
		OptionRouter:           []byte(subnet.DefaultGW.To4()),
		OptionDomainNameServer: []byte(subnet.DNSServer.To4()),
	}

	maxTime := time.Now().Add(time.Hour * 24 * 365 * 10) // 10 years

	// Network address is reserved
	i := subnet.LAN.IP[3]
	subnet.leases[i].State = StateReserved
	subnet.leases[i].IP = net.IPv4zero
	subnet.leases[i].DHCPExpiry = maxTime

	// Broadcast address is reserved
	i = subnet.broadcast[3]
	subnet.leases[i].State = StateReserved
	subnet.leases[i].IP = net.IPv4zero
	subnet.leases[i].DHCPExpiry = maxTime

	if subnet.LAN.Contains(subnet.DHCPServer) {
		i = subnet.DHCPServer[3]
		subnet.leases[i].State = StateReserved
		subnet.leases[i].IP = subnet.DHCPServer
		subnet.leases[i].DHCPExpiry = maxTime
	}
	if subnet.LAN.Contains(subnet.DNSServer) {
		i = subnet.DNSServer[3]
		subnet.leases[i].State = StateReserved
		subnet.leases[i].IP = subnet.DNSServer
		subnet.leases[i].DHCPExpiry = maxTime
	}
	if subnet.LAN.Contains(subnet.DefaultGW) {
		i = subnet.DefaultGW[3]
		subnet.leases[i].State = StateReserved
		subnet.leases[i].IP = subnet.DefaultGW
		subnet.leases[i].DHCPExpiry = maxTime
	}

	if debugging() {
		log.Infof("dhcp4: subnet lan=%s gw=%s dhcp=%s dns=%s dur=%v options=%+v",
			subnet.LAN, subnet.DefaultGW, subnet.DHCPServer, subnet.DNSServer, subnet.Duration, subnet.options)
		subnet.printSubnet()
	}

	return &subnet, nil
}

func (h *dhcpSubnet) appendRouteOptions(ip net.IP, mask net.IPMask, routeTo net.IP) {

	h.options[OptionPerformRouterDiscovery] = []byte{0} // don't perform router discovery
	h.options[OptionStaticRoute] = append([]byte(ip.To4()), []byte(routeTo.To4())...)

	// Classless Route Option Format (override Static Route if requested)
	// The code for this option is 121, and its minimum length is 5 bytes.
	// This option can contain one or more static routes, each of which
	// consists of a destination descriptor and the IP address of the router
	// that should be used to reach that destination.
	//
	// Code Len Destination 1    Router 1
	// +-----+---+----+-----+----+----+----+----+----+
	// | 121 | n | d1 | ... | dN | r1 | r2 | r3 | r4 |
	// +-----+---+----+-----+----+----+----+----+----+
	// The destination encoding consists of one octet describing the width of the subnet mask,
	// followed by all the significant octets of the subnet number.
	// see https://tools.ietf.org/html/rfc3442

	ones, _ := mask.Size()
	octects := uint8(ones / 8)
	if ones%8 != 0 {
		octects++
	}
	buf := make([]byte, octects+4+1)
	buf[0] = uint8(ones)
	copy(buf[1:], mask[:octects])
	copy(buf[1+octects:], routeTo.To4())
	h.options[OptionClasslessRouteFormat] = buf
}

func (h *dhcpSubnet) printSubnet() {
	count, free := h.countLeases()
	start := uint(h.LAN.IP[3])
	end := uint(h.broadcast[3])
	log.Infof("dhcp4: table - len %v, count %v, free %v, start %v, end %v", len(h.leases), count, free, start, end)
	for i := start; i <= end; i++ {
		v := h.leases[i]
		if v.State != StateFree {
			log.Infof("dhcp4: lease %3d %10s %d %24s %18s %15s %v", i, v.State, v.ClientID, v.Name, v.MAC, v.IP, v.DHCPExpiry.Format("2006-01-02 15:04"))
		}
	}
}

func (h *dhcpSubnet) getLeases() (table []Lease) {
	start := uint(h.FirstIP[3])
	end := uint(h.LastIP[3])
	for i := start; i <= end; i++ {
		if h.leases[i].State != StateFree {
			table = append(table, h.leases[i])
		}
	}
	return table
}

func (h *dhcpSubnet) findCliendID(id []byte) *Lease {
	start := uint(h.FirstIP[3])
	end := uint(h.LastIP[3])
	for i := start; i <= end; i++ {
		if bytes.Equal(h.leases[i].ClientID, id) {
			return &h.leases[i]
		}
	}
	return nil
}

func (h *dhcpSubnet) findIP(ip net.IP) *Lease {
	start := uint(h.FirstIP[3])
	end := uint(h.LastIP[3])
	for i := start; i <= end; i++ {
		if h.leases[i].IP.Equal(ip) {
			return &h.leases[i]
		}
	}
	return nil
}

func (h *dhcpSubnet) findMAC(mac net.HardwareAddr) *Lease {
	start := uint(h.FirstIP[3])
	end := uint(h.LastIP[3])
	for i := start; i <= end; i++ {
		if bytes.Equal(h.leases[i].MAC, mac) {
			return &h.leases[i]
		}
	}
	return nil
}

func freeLease(lease *Lease) {
	if lease == nil {
		return
	}

	if debugging() {
		log.WithFields(log.Fields{"clientID": lease.ClientID, "mac": lease.MAC, "ip": lease.IP}).Trace("dhcp4: free lease")
	}
	lease.ClientID = []byte{}
	lease.XID = []byte{}
	lease.MAC = net.HardwareAddr{}
	lease.IP = net.IPv4zero
	lease.State = StateFree
	lease.Count = 0
}

// newLease allocates a new IP from the dhcpSubnet.
//                it works on relative index
func (h *dhcpSubnet) newLease(state string, clientID []byte, reqMAC net.HardwareAddr, reqIP net.IP, xID []byte) (lease *Lease) {

	// Attempt to reuse IP if given and IP in correct LAN
	if reqIP != nil && !reqIP.IsUnspecified() && h.LAN.Contains(reqIP) {
		lease := &h.leases[reqIP.To4()[3]]
		if lease.State == StateFree {
			lease.State = state
			lease.ClientID = dupBytes(clientID) // copy to release packet buffer
			lease.XID = dupBytes(xID)
			lease.MAC = dupMAC(reqMAC)
			lease.IP = dupIP(reqIP)
			lease.DHCPExpiry = time.Now().Add(1 * time.Minute)

			if debugging() {
				log.WithFields(log.Fields{"ip": lease.IP, "mac": lease.MAC, "clientID": lease.ClientID, "xid": lease.XID}).Trace("dhcp4: new lease reusing IP")
			}
			return lease
		}
	}

	// Release expired entries
	h.freeEntries()

	ip := dupIP(h.LAN.IP).To4() // copy to update array
	end := uint(h.LastIP[3])

	// Find free IP
	if debugging() {
		log.Tracef("dhcp4: looking up free IP from %v to %v", h.nextIP, end)
	}

	for h.nextIP <= end {
		index := h.nextIP
		// log.Info("nexip ", h.nextIP, lastIP, index)
		if h.leases[index].State == StateFree {
			lease = &h.leases[index]
			ip[3] = byte(h.nextIP)
			lease.State = StateDiscovery
			lease.ClientID = dupBytes(clientID) // copy to release packet buffer
			lease.XID = dupBytes(xID)
			lease.MAC = dupMAC(reqMAC)
			lease.IP = ip                                      // no need to copy, already a new copy
			lease.DHCPExpiry = time.Now().Add(1 * time.Minute) // wait for dhcp request packet
			h.nextIP = h.nextIP + 1
			break
		}
		h.nextIP = h.nextIP + 1
	}

	// second pass
	// If all IPs are allocated, search at begining of table
	if lease == nil {
		h.nextIP = uint(h.FirstIP[3])
		//h.printSubnet()

		// only search again if there are free leases
		_, free := h.countLeases()
		if free == 0 {
			log.Error("dhcp4: exhausted all IPs")
			return nil
		}
		lease = h.newLease(state, clientID, reqMAC, reqIP, xID)
	}

	if debugging() {
		log.WithFields(log.Fields{"ip": lease.IP.String(), "mac": lease.MAC.String()}).Debug("dhcp4: new lease allocated IP")
	}

	return lease
}

func (h *dhcpSubnet) freeEntries() {
	now := time.Now()

	count, free := h.countLeases()
	if debugging() {
		log.Trace("dhcp4: free expired leases - before ", count, free)
	}

	// Find free IP
	start := uint(h.FirstIP[3])
	end := uint(h.LastIP[3])
	for i := start; i <= end; i++ {
		if h.leases[i].State == StateReserved {
			continue

		}
		if h.leases[i].State != StateFree && h.leases[i].DHCPExpiry.Before(now) {
			freeLease(&h.leases[i])
		}

	}

	count, free = h.countLeases()
	if debugging() {
		log.Trace("dhcp4: free expired leases - after ", count, free)
	}
}

func (h *dhcpSubnet) countLeases() (count uint, free uint) {

	start := uint(h.FirstIP[3])
	end := uint(h.LastIP[3])
	for i := start; i <= end; i++ {
		if h.leases[i].State != StateFree && h.leases[i].State != StateReserved {
			count = count + 1
		}
		if h.leases[i].State == StateFree {
			free = free + 1
		}
	}
	return count, free
}

// MarshalYAML implements the YAML marshalling interface
func (h *leaseTable) MarshalYAML() (interface{}, error) {
	tmp := []Lease{}
	for i := 0; i < len(h); i++ {
		if h[i].State == StateAllocated {
			tmp = append(tmp, h[i])
		}
	}

	return tmp, nil
}

// UnmarshalYAML implements the YAML marshalling interface
func (h *leaseTable) UnmarshalYAML(unmarshal func(interface{}) error) error {
	tmp := []Lease{}

	err := unmarshal(&tmp)
	if err != nil {
		return err
	}

	for i := range tmp {
		if tmp[i].IP == nil {
			continue
		}
		index := tmp[i].IP.To4()[3]
		h[index].State = stringToState(tmp[i].State)
		h[index].Name = tmp[i].Name
		h[index].ClientID = dupBytes(tmp[i].ClientID)
		h[index].IP = dupIP(tmp[i].IP)
		h[index].MAC = dupMAC(tmp[i].MAC)
		h[index].DHCPExpiry = tmp[i].DHCPExpiry

		if tracing() {
			log.Tracef("dhcp4: unmarshall %v lease=%+v ", index, h[index])
		}
	}

	return nil
}

func (h *Handler) migrate() {

}

func loadConfig(fname string) (net1 *dhcpSubnet, net2 *dhcpSubnet, err error) {

	if fname == "" {
		return
	}

	table := struct {
		Net1    *SubnetConfig
		Net2    *SubnetConfig
		Leases1 *leaseTable
		Leases2 *leaseTable
	}{}

	source, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Errorf("Cannot read dhcp file: %s error %s", fname, err)
		return nil, nil, err
	}

	// Unmarshall will load a table with 256 leases
	err = yaml.Unmarshal(source, &table)
	if err != nil {
		log.Errorf("Cannot parse dhcp file: %s error %s", fname, err)
		return nil, nil, err
	}

	// Validate net1 configuration to ensure IPs are good
	if table.Net1 != nil {
		net1, err = newSubnet(SubnetConfig{
			LAN:        table.Net1.LAN,
			DefaultGW:  table.Net1.DefaultGW,
			DHCPServer: table.Net1.DHCPServer,
			DNSServer:  table.Net1.DNSServer,
			Duration:   table.Net1.Duration,
			FirstIP:    table.Net1.FirstIP,
			LastIP:     table.Net1.LastIP})
		if err != nil {
			return nil, nil, fmt.Errorf("fail to load net1 : %w", err)
		}

		// table.Leases1 contains the full 256 entries table
		for i := range table.Leases1 {
			if table.Leases1[i].State != StateAllocated {
				continue
			}

			if table.Leases1[i].IP == nil || !net1.LAN.Contains(table.Leases1[i].IP) || net1.leases[i].State == StateReserved {
				continue
			}

			*(&net1.leases[i]) = *(&table.Leases1[i])
		}
	}

	if table.Net2 != nil {
		net2, err = newSubnet(SubnetConfig{
			LAN:        table.Net2.LAN,
			DefaultGW:  table.Net2.DefaultGW,
			DHCPServer: table.Net2.DHCPServer,
			DNSServer:  table.Net2.DNSServer,
			Duration:   table.Net2.Duration,
			FirstIP:    table.Net2.FirstIP,
			LastIP:     table.Net2.LastIP})
		if err != nil {
			return nil, nil, fmt.Errorf("fail to load net1 : %w", err)
		}

		// table.Leases2 contains the full 256 entries table
		for i := range table.Leases2 {
			if table.Leases2[i].State != StateAllocated {
				continue
			}

			if table.Leases2[i].IP == nil || !net2.LAN.Contains(table.Leases2[i].IP) || net2.leases[i].State == StateReserved {
				continue
			}

			*(&net2.leases[i]) = *(&table.Leases2[i])
		}
	}

	return net1, net2, nil
}

func (h *Handler) saveConfig(fname string) (err error) {

	if fname == "" {
		return
	}

	table := struct {
		Net1    *SubnetConfig
		Net2    *SubnetConfig
		Leases1 *leaseTable
		Leases2 *leaseTable
	}{Net1: &h.net1.SubnetConfig, Net2: &h.net2.SubnetConfig, Leases1: &h.net1.leases, Leases2: &h.net2.leases}

	stream, err := yaml.Marshal(&table)
	if err != nil {
		log.Errorf("Cannot marshall dhcp file: %s error %s", fname, err)
		return err
	}

	err = ioutil.WriteFile(fname, stream, os.ModePerm)
	if err != nil {
		log.Errorf("Cannot write dhcp file: %s error %s", fname, err)
		return err
	}

	return nil
}

// Make sure strings are mapped to same constant address for faster comparison
func stringToState(s string) string {
	if s == StateAllocated {
		return StateAllocated
	}
	if s == StateDiscovery {
		return StateDiscovery
	}
	if s == StateReserved {
		return StateReserved
	}
	return StateFree
}
