package dhcp4

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/irai/packet"
	yaml "gopkg.in/yaml.v2"
)

// SubnetConfig hold configuration values for the subnet
//
// DefaultGW must be accessible in the subnet
// example: lan 192.168.0.0/24, gw 192.168.0.1
//          lan 192.168.0.128/25, gw 192.168.0.129
type SubnetConfig struct {
	LAN        net.IPNet        // lan address & netmask
	DefaultGW  net.IP           // Default Gateway for subnet
	DHCPServer net.IP           // DHCP server ID
	DNSServer  net.IP           // DNS server IP
	FirstIP    net.IP           // First IP in range
	LastIP     net.IP           // Last IP in range
	Duration   time.Duration    // lease duration
	Stage      packet.HuntStage // Default stage for subnet
	ID         string           // Used for logging
}

// dhcpSubnet hold the 256 lease array for subnet
// We use the last byte in IPv4 as the index.
type dhcpSubnet struct {
	SubnetConfig         // anonymous struct
	broadcast    net.IP  // hold the net broadcast IP
	options      Options // Options to send to DHCP Clients
	nextIP       uint
}

// newSubnet create a subnet structure to track lease allocation.
func newSubnet(config SubnetConfig) (*dhcpSubnet, error) {

	config.LAN.IP = config.LAN.IP.Mask(config.LAN.Mask) // ensure this is a network address

	subnet := dhcpSubnet{}
	subnet.LAN = net.IPNet{IP: config.LAN.IP.Mask(config.LAN.Mask).To4(), Mask: config.LAN.Mask}
	subnet.ID = config.ID

	// get broadcast addr
	subnet.broadcast = packet.CopyIP(subnet.LAN.IP).To4()
	for i := range subnet.broadcast { // range over the 4 bytes
		subnet.broadcast[i] = subnet.broadcast[i] | ^subnet.LAN.Mask[i]
	}

	// default values for first and last IPs
	config.FirstIP = packet.CopyIP(config.FirstIP).To4() // must copy, we are updating the array
	if config.FirstIP == nil || config.FirstIP.Equal(net.IPv4zero) || config.FirstIP[3] <= subnet.LAN.IP[3] {
		config.FirstIP = packet.CopyIP(subnet.LAN.IP).To4()
		config.FirstIP[3] = config.FirstIP[3] + 1
	}
	config.LastIP = packet.CopyIP(config.LastIP).To4() // must copy, we are updating the array
	if config.LastIP == nil || config.LastIP.Equal(net.IPv4zero) || config.LastIP[3] > subnet.broadcast[3] {
		config.LastIP = packet.CopyIP(subnet.broadcast).To4()
		config.LastIP[3] = config.LastIP[3] - 1
	}
	subnet.Duration = config.Duration
	if subnet.Duration == 0 {
		subnet.Duration = 4 * time.Hour
	}
	subnet.Stage = config.Stage
	if subnet.Stage != packet.StageNormal && subnet.Stage != packet.StageRedirected {
		return nil, fmt.Errorf("invalid subnet stage")
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

	if Debug {
		fmt.Printf("dhcp4: createSubnet %+v", config)
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
		OptionServerIdentifier: []byte(subnet.DHCPServer),
		OptionSubnetMask:       []byte(subnet.LAN.Mask), // must occur before router - need to sort the map
		OptionRouter:           []byte(subnet.DefaultGW.To4()),
		OptionDomainNameServer: []byte(subnet.DNSServer.To4()),
	}

	if Debug {
		fmt.Printf("dhcp4: subnet lan=%s gw=%s dhcp=%s dns=%s dur=%v options=%+v",
			subnet.LAN, subnet.DefaultGW, subnet.DHCPServer, subnet.DNSServer, subnet.Duration, subnet.options)
	}

	return &subnet, nil
}

// CopyOptions returns the default options for this subnet
func (h *dhcpSubnet) CopyOptions() Options {
	opts := make(Options, len(h.options)+5)
	for k, v := range h.options {
		opts[k] = v
	}
	return opts
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

func loadConfig(fname string) (net1 *dhcpSubnet, net2 *dhcpSubnet, t leaseTable, err error) {
	if fname == "" {
		return
	}
	source, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, nil, nil, err
	}
	return loadByteArray(source)
}

func loadByteArray(source []byte) (net1 *dhcpSubnet, net2 *dhcpSubnet, t leaseTable, err error) {
	table := struct {
		Net1   *SubnetConfig
		Net2   *SubnetConfig
		Leases []Lease
	}{}

	// err = yaml.UnmarshalStrict(source, &table)
	err = yaml.Unmarshal(source, &table)
	if err != nil {
		return nil, nil, nil, err
	}

	// Validate net1 configuration to ensure IPs are good
	if table.Net1 != nil {
		net1, err = newSubnet(SubnetConfig{
			LAN:        table.Net1.LAN,
			DefaultGW:  table.Net1.DefaultGW,
			DHCPServer: table.Net1.DHCPServer,
			DNSServer:  table.Net1.DNSServer,
			Duration:   table.Net1.Duration,
			Stage:      table.Net1.Stage,
			FirstIP:    table.Net1.FirstIP,
			LastIP:     table.Net1.LastIP})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("fail to load net1 : %w", err)
		}
	}

	if table.Net2 != nil {
		net2, err = newSubnet(SubnetConfig{
			LAN:        table.Net2.LAN,
			DefaultGW:  table.Net2.DefaultGW,
			DHCPServer: table.Net2.DHCPServer,
			DNSServer:  table.Net2.DNSServer,
			Duration:   table.Net2.Duration,
			Stage:      table.Net2.Stage,
			FirstIP:    table.Net2.FirstIP,
			LastIP:     table.Net2.LastIP})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("fail to load net1 : %w", err)
		}
	}

	tt := map[string]*Lease{}

	// Careful: Yaml does not set private fields in unmarshaled structured.
	//          so the v.subnet is nil and will cause a fatal error
	if table.Leases != nil {
		for _, v := range table.Leases {
			// MUST set v.subnet before printing to avoid fatal error
			//      when printing v
			v.subnet = net1

			if v.State != StateAllocated {
				fmt.Printf("dhcp4: load config invalid state %v \n", v)
				continue
			}

			if v.Addr.IP == nil || !net1.LAN.Contains(v.Addr.IP) {
				fmt.Printf("dhcp4: load config invalid LAN %v \n", v)
				continue
			}
			if v.ClientID == nil || len(v.ClientID) == 0 {
				fmt.Printf("dhcp4: load config invalid clientID %v \n", v)
				continue
			}

			if net2.LAN.Contains(v.Addr.IP) {
				v.subnet = net2
			}
			l := Lease{}
			l = v
			tt[string(v.ClientID)] = &l
		}
	}

	return net1, net2, tt, nil
}

func (h *Handler) saveConfig(fname string) (err error) {

	if fname == "" {
		return
	}

	table := struct {
		Net1   *SubnetConfig
		Net2   *SubnetConfig
		Leases []Lease
	}{Net1: &h.net1.SubnetConfig, Net2: &h.net2.SubnetConfig}

	for _, v := range h.table {
		if v.State == StateAllocated {
			table.Leases = append(table.Leases, *v)
		}
	}

	stream, err := yaml.Marshal(&table)
	if err != nil {
		fmt.Printf("error cannot marshall dhcp file: %s error %s", fname, err)
		return err
	}

	err = ioutil.WriteFile(fname, stream, os.ModePerm)
	if err != nil {
		fmt.Printf("error cannot write dhcp file: %s error %s", fname, err)
		return err
	}

	return nil
}
