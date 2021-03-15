// +build !arp

package dhcp4

import (
	"fmt"
	"net"
	"testing"

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

func Test_Subnet_Save(t *testing.T) {

	// log.SetLevel(log.DebugLevel)
	// Debug = true
	filename := t.TempDir() + "/dhcpconfig.yaml"

	// filename := "./dhcpconfig.yaml"
	// os.Remove(filename)

	tc := setupTestHandler()
	defer tc.Close()

	checkLeaseTable(t, tc, 0, 0, 0)

	// lease 1
	lease := tc.h.findOrCreate(mac1, mac1, "mac1")
	tc.h.allocIPOffer(lease, nil)
	lease.State = StateDiscover

	// lease 2
	lease = tc.h.findOrCreate(mac2, mac2, "mac2")
	lease.Addr.IP = ip2
	lease.State = StateAllocated

	// lease 3
	lease = tc.h.findOrCreate(mac3, mac3, "mac3")
	tc.h.allocIPOffer(lease, nil)
	lease.Addr.IP = lease.IPOffer
	// lease.IPOffer = nil
	lease.State = StateAllocated

	// lease 4
	lease = tc.h.findOrCreate(mac4, mac4, "mac4")

	checkLeaseTable(t, tc, 2, 1, 1)

	if err := tc.h.saveConfig(filename); err != nil {
		t.Fatal("cannot save", err)
	}

	net1, net2, leases, err := loadConfig(filename)
	if err != nil {
		t.Fatalf("unexpected error in lease file %v", err)
		return
	}

	if !net1.LAN.IP.Equal(tc.h.net1.LAN.IP) || !net1.DHCPServer.Equal(tc.h.net1.DHCPServer) {
		t.Errorf("unexpected net1 %+v, h.net1 %+v ", net1, tc.h.net1)
	}
	if !net2.LAN.IP.Equal(tc.h.net2.LAN.IP) || !net2.DHCPServer.Equal(tc.h.net2.DHCPServer) {
		t.Errorf("unexpected net2 %+v", net2)
	}

	if n := len(leases); n != 2 {
		t.Errorf("unexpected leases want=%d got=%v", 2, n)
		fmt.Println(leases)
		tc.h.printTable()
	}

}

/****
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
  ***/
