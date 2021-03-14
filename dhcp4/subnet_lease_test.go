// +build !arp

package dhcp4

import (
	"net"

	log "github.com/sirupsen/logrus"
)

const testDHCPFilename = "./testDHCPConfig.yml"

type netStruct struct {
	home      SubnetConfig
	netfilter SubnetConfig
}

var (
	// test table: add subnet combinations here to test the model
	//
	nets = []netStruct{
		{
			home: SubnetConfig{
				LAN:        net.IPNet{IP: net.ParseIP("192.168.0.0").To4(), Mask: net.CIDRMask(24, 32)},
				DefaultGW:  net.ParseIP("192.168.0.1").To4(),
				DHCPServer: net.ParseIP("192.168.0.1").To4(),
				FirstIP:    net.ParseIP("192.168.0.1").To4(),
				LastIP:     net.ParseIP("192.168.0.255").To4(),
				DNSServer:  dns1,
			},
			netfilter: SubnetConfig{
				LAN:        net.IPNet{IP: net.ParseIP("192.168.0.128").To4(), Mask: net.CIDRMask(25, 32)},
				DefaultGW:  net.ParseIP("192.168.0.129").To4(),
				DHCPServer: net.ParseIP("192.168.0.129").To4(),
				FirstIP:    net.ParseIP("192.168.0.129").To4(),
				LastIP:     net.ParseIP("192.168.0.255").To4(),
				DNSServer:  dns2,
			},
		},
		{
			home: SubnetConfig{
				LAN:       net.IPNet{IP: net.ParseIP("192.168.1.1").To4(), Mask: net.CIDRMask(24, 32)},
				DefaultGW: net.ParseIP("192.168.1.130").To4(), DHCPServer: net.ParseIP("192.168.1.10").To4(), DNSServer: dns1,
				FirstIP: net.ParseIP("192.168.1.1").To4(),
				LastIP:  net.ParseIP("192.168.1.255").To4(),
			},
			netfilter: SubnetConfig{
				LAN:       net.IPNet{IP: net.ParseIP("192.168.1.0").To4(), Mask: net.CIDRMask(25, 32)},
				DefaultGW: net.ParseIP("192.168.1.10").To4(), DHCPServer: net.ParseIP("192.168.1.10").To4(), DNSServer: dns1,
				FirstIP: net.ParseIP("192.168.1.1").To4(),
				LastIP:  net.ParseIP("192.168.1.90").To4(),
			},
		},
		{
			home: SubnetConfig{
				LAN:       net.IPNet{IP: net.ParseIP("192.168.70.1").To4(), Mask: net.CIDRMask(24, 32)},
				DefaultGW: net.ParseIP("192.168.70.254").To4(), DHCPServer: net.ParseIP("192.168.70.1").To4(), DNSServer: dns1,
				FirstIP: net.ParseIP("192.168.70.1").To4(),
				LastIP:  net.ParseIP("192.168.70.255").To4(),
			},
			netfilter: SubnetConfig{
				LAN:       net.IPNet{IP: net.ParseIP("192.168.70.0").To4(), Mask: net.CIDRMask(25, 32)},
				DefaultGW: net.ParseIP("192.168.70.1").To4(), DHCPServer: net.ParseIP("192.168.70.1").To4(), DNSServer: dns1,
				FirstIP: net.ParseIP("192.168.70.50").To4(),
				LastIP:  net.ParseIP("192.168.70.127").To4(),
			},
		},
		{
			home: SubnetConfig{
				LAN:       net.IPNet{IP: net.ParseIP("192.168.0.0").To4(), Mask: net.CIDRMask(24, 32)},
				DefaultGW: net.ParseIP("192.168.0.254").To4(), DHCPServer: net.ParseIP("192.168.0.1").To4(), DNSServer: dns1,
				FirstIP: net.ParseIP("192.168.0.1").To4(),
				LastIP:  net.ParseIP("192.168.0.255").To4(),
			},
			netfilter: SubnetConfig{
				LAN:       net.IPNet{IP: net.ParseIP("192.168.70.0").To4(), Mask: net.CIDRMask(25, 32)},
				DefaultGW: net.ParseIP("192.168.70.1").To4(), DHCPServer: net.ParseIP("192.168.70.1").To4(), DNSServer: dns1,
				FirstIP: net.ParseIP("192.168.70.40").To4(),
				LastIP:  net.ParseIP("192.168.70.50").To4(),
			},
		},
	}

	dns1 = net.ParseIP("8.8.8.8")
	dns2 = net.ParseIP("8.8.8.9")

	mac0 = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0x0}
)

func setupSubnets() (net1 *dhcpSubnet, net2 *dhcpSubnet) {

	// 192.168.0.0
	config := SubnetConfig{
		LAN:        net.IPNet{IP: net.ParseIP("192.168.0.0").To4(), Mask: net.CIDRMask(24, 32)},
		DefaultGW:  net.ParseIP("192.168.0.1").To4(),
		DHCPServer: net.ParseIP("192.168.0.1").To4(),
		FirstIP:    net.ParseIP("192.168.0.0").To4(),
		LastIP:     net.ParseIP("192.168.0.255").To4(),
		DNSServer:  dns1,
	}
	net1, err1 := newSubnet(config)
	// net1.printSubnet()

	config = SubnetConfig{
		LAN:        net.IPNet{IP: net.ParseIP("192.168.0.128").To4(), Mask: net.CIDRMask(25, 32)},
		DefaultGW:  net.ParseIP("192.168.0.129").To4(),
		DHCPServer: net.ParseIP("192.168.0.129").To4(),
		FirstIP:    net.ParseIP("192.168.0.130").To4(),
		LastIP:     net.ParseIP("192.168.0.240").To4(),
		DNSServer:  dns2,
	}
	net2, err2 := newSubnet(config)
	// net2.printSubnet()

	if net1 == nil || net2 == nil {
		log.Fatal("cannot create subnets", err1, err2)
	}

	return net1, net2
}

/****


func Test_Subnet_Save(t *testing.T) {

	os.Remove(testDHCPFilename)

	h := Handler{}

	h.net1, _ = newSubnet(nets[0].home)
	h.net1.Duration = 2 * time.Hour
	h.net2, _ = newSubnet(nets[0].netfilter)

	l := h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	l = h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	l.State = StateAllocated
	l = h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	l.State = StateAllocated

	// invalid IP
	l = h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	l.IP = net.IPv4(192, 168, 30, 0)

	count2, _ := h.net2.countLeases()
	if count2 != 4 {
		h.net1.printSubnet()
		t.Error("invalid count ", count2)
		return
	}
	err := h.saveConfig(testDHCPFilename)
	if err != nil {
		t.Error("cannot save", err)
		return
	}

}

func Test_Subnet_Load(t *testing.T) {

	tc := setupTestHandler()
	defer tc.Close()
	// h, _ := New(nets[0].home, nets[0].netfilter, testDHCPFilename)

	if tc.h.net1.Duration != 4*time.Hour {
		t.Error("invalid duration ", tc.h.net1.Duration)
	}
	clientID1 := []byte{0x01, 0x01}
	clientID2 := []byte{0x02, 0x02}

	l := tc.h.net2.newLease(StateDiscovery, clientID1, mac1, ip1, nil)
	l.State = StateAllocated
	l = tc.h.net2.newLease(StateDiscovery, clientID1, mac1, ip1, nil)
	l.State = StateAllocated
	l = tc.h.net2.newLease(StateDiscovery, clientID2, mac2, ip2, nil)
	l.State = StateAllocated

	count1, _ := tc.h.net1.countLeases()
	count2, _ := tc.h.net2.countLeases()
	if count1 != 0 || count2 != 3 {
		tc.h.net1.printSubnet()
		t.Error("invalid count ", count1, count2)
		return
	}
	if debugging() {
		tc.h.net1.printSubnet()
	}

}
func Test_Migration(t *testing.T) {

	h := Handler{}
	h.net1, _ = newSubnet(nets[0].home)

	err := yaml.Unmarshal(testMigrationFile, &h.net1.leases)
	if err != nil {
		t.Error("cannot parse byte array", err)
		return
	}

	count1, _ := h.net1.countLeases()
	if count1 != 2 {
		h.net1.printSubnet()
		h.net2.printSubnet()
		t.Error("invalid count ", count1)
		return
	}

}

var testMigrationFile = []byte(`
- state: allocated
  name: "v1.1migration 2"
  mac:
  - 255
  - 255
  - 255
  - 255
  - 255
  - 2
  ip: 192.168.0.2
  dhcpexpiry: 2020-04-29T08:19:05.0460045+10:00
- state: allocated
  name: "v1.1migration 1"
  mac:
  - 255
  - 255
  - 255
  - 255
  - 255
  - 1
  ip: 192.168.0.3
  dhcpexpiry: 2020-04-29T08:19:05.0460119+10:00
  `)

func Test_newSubnet(t *testing.T) {
	type args struct {
		config SubnetConfig
	}
	tests := []struct {
		name    string
		args    args
		want    *dhcpSubnet
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newSubnet(tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("newSubnet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newSubnet() = %v, want %v", got, tt.want)
			}
		})
	}
}
*****/
