// +build !arp

package dhcp4

import (
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
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

func Test_Subnet2(t *testing.T) {
	for i := range nets {
		net1, _ := newSubnet(nets[i].home)
		net2, _ := newSubnet(nets[i].netfilter)

		if net1 == nil || net2 == nil {
			t.Error("cannot create subnets")
			return
		}

		if !net1.DNSServer.Equal(nets[i].home.DNSServer) || !net2.DNSServer.Equal(nets[i].netfilter.DNSServer) {
			t.Error("invalid dns", net1.DNSServer, nets[i].home.DNSServer, net2.DNSServer, nets[i].netfilter.DNSServer)
			return
		}

		net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
		l1 := net2.newLease(StateDiscovery, mac1, mac1, nil, nil)
		count1, _ := net1.countLeases()
		count2, _ := net2.countLeases()
		if count1 != 0 || count2 != 2 {
			net1.printSubnet()
			net2.printSubnet()
			t.Error("invalid count ", count1, count2)
			return
		}

		freeLease(net1.findCliendID(l1.MAC))
		count1, _ = net1.countLeases()
		count2, _ = net2.countLeases()
		if count1 != 0 || count2 != 2 {
			net2.printSubnet()
			t.Error("invalid count 2", count1, count2)
			return
		}
	}
}

func Test_Subnet(t *testing.T) {

	net1, net2 := setupSubnets()

	l1 := net1.newLease(StateDiscovery, mac0, mac0, nil, nil)

	count1, _ := net1.countLeases()
	count2, _ := net2.countLeases()
	if count1 != 1 || count2 != 0 {
		t.Error("1 - invalid leases count", count1, count2)
		return
	}

	net2.newLease(StateDiscovery, mac1, mac1, nil, nil)
	net2.newLease(StateDiscovery, mac1, mac1, nil, nil)
	net2.newLease(StateDiscovery, mac1, mac1, nil, nil)
	count1, _ = net1.countLeases()
	count2, _ = net2.countLeases()
	if count1 != 1 || count2 != 3 {
		t.Error("2 - invalid leases count", count1, count2)
		return
	}

	// l1.State = StateAllocated
	l3 := net1.newLease(StateDiscovery, mac2, mac2, nil, nil)
	freeLease(l1)
	freeLease(l3)
	count1, _ = net1.countLeases()
	count2, _ = net2.countLeases()
	if count1 != 0 || count2 != 3 {
		t.Error("3 - invalid leases count", count1, count2)
		return
	}

	net1.printSubnet()
	net2.printSubnet()
}

func Test_Subnet_DHCP_Exhaust(t *testing.T) {

	// we use 3 reserved slots .00, .01, .255
	config := SubnetConfig{
		LAN:        net.IPNet{IP: net.ParseIP("192.168.0.0").To4(), Mask: net.CIDRMask(24, 32)},
		DefaultGW:  net.ParseIP("192.168.0.1").To4(),
		DHCPServer: net.ParseIP("192.168.0.1").To4(),
		// FirstIP:    net.ParseIP("192.168.0.0").To4(),
		// LastIP:     net.ParseIP("192.168.0.255").To4(),
		DNSServer: dns1,
	}

	net1, err := newSubnet(config)
	if err != nil {
		t.Fatal("cannot create subnet ", err)
	}

	mac0 := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0x0}
	mac1 := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0x01, 0x0}

	n := 253
	for i := 0; i < n; i++ {
		mac, _ := net.ParseMAC(mac0.String())
		mac[5] = byte(i)

		l1 := net1.newLease(StateDiscovery, mac, mac, nil, nil)
		if l1 == nil {
			net1.printSubnet()
			t.Error("Exausted all IPs")
			return
		}
	}

	l1 := net1.newLease(StateDiscovery, mac1, mac1, nil, nil)
	count1, _ := net1.countLeases()
	if l1 != nil || count1 != uint(n) {
		t.Error("Found incorrect IPs", count1)
		return
	}

	freeLease(net1.findCliendID(mac0))
	l1 = net1.newLease(StateDiscovery, mac1, mac1, nil, nil)
	count1, _ = net1.countLeases()
	if l1 == nil || count1 != uint(n) {
		t.Error("Error IPs", count1)
		return
	}
}

func Test_Subnet_DHCP_Exhaust_With_Free(t *testing.T) {

	n := 2048
	net1, _ := setupSubnets()

	mac0 = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0x0}
	mac1 = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0x01, 0x0}
	for i := 0; i < n; i++ {
		mac, _ := net.ParseMAC(mac0.String())
		mac[5] = byte(i)

		l1 := net1.newLease(StateDiscovery, mac, mac, nil, nil)
		if l1 == nil {
			net1.printSubnet()
			t.Error("Exausted all IPs")
			return
		}
		freeLease(l1)
	}

	// log.Infof("net1 %+v", net1)
	l1 := net1.newLease(StateDiscovery, mac1, mac1, nil, nil)
	count1, _ := net1.countLeases()
	if l1 == nil || count1 != 1 {
		t.Error("Error IPs", count1)
		return
	}

	l1 = net1.newLease(StateDiscovery, mac1, mac1, nil, nil)
	count1, _ = net1.countLeases()
	if l1 == nil || count1 != 2 {
		t.Error("Error IPs", count1)
		return
	}
}

func Test_Subnet_Save(t *testing.T) {

	os.Remove(testDHCPFilename)

	h := DHCPHandler{}

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

	if tc.h.net1.Duration != 2*time.Hour {
		t.Error("invalid duration ", tc.h.net1.Duration)
	}

	l := tc.h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	l.State = StateAllocated
	l = tc.h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	l.State = StateAllocated
	l = tc.h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	l.State = StateAllocated

	count1, _ := tc.h.net1.countLeases()
	count2, _ := tc.h.net2.countLeases()
	if count1 != 0 || count2 != 5 {
		tc.h.net1.printSubnet()
		t.Error("invalid count ", count1, count2)
		return
	}
	if debugging() {
		tc.h.net1.printSubnet()
	}

}
func Test_Migration(t *testing.T) {

	h := DHCPHandler{}
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
