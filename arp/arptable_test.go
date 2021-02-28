package arp

import (
	"net"
	"testing"

	"github.com/irai/packet"
)

var (
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

	hostMAC   = net.HardwareAddr{0x00, 0xff, 0x03, 0x04, 0x05, 0x01} // key first byte zero for unicast mac
	hostIP    = net.ParseIP("192.168.0.129").To4()
	homeLAN   = net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}
	routerMAC = net.HardwareAddr{0x00, 0xff, 0x03, 0x04, 0x05, 0x11} // key first byte zero for unicast mac
	routerIP  = net.ParseIP("192.168.0.11").To4()
	ip1       = net.ParseIP("192.168.0.1").To4()
	ip2       = net.ParseIP("192.168.0.2").To4()
	ip3       = net.ParseIP("192.168.0.3").To4()
	ip4       = net.ParseIP("192.168.0.4").To4()
	ip5       = net.ParseIP("192.168.0.5").To4()
	mac1      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5      = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x05}
	localIP   = net.IPv4(169, 254, 0, 10).To4()
	localIP2  = net.IPv4(169, 254, 0, 11).To4()
)

func Test_AddSimple(t *testing.T) {

	tc := setupTestHandler(t)
	defer tc.Close()

	packet.Debug = true

	MACEntry, _ := tc.arp.virtual.upsert(StateNormal, mac1, ip4)

	if MACEntry != tc.arp.virtual.findByMAC(mac1) || MACEntry != tc.arp.virtual.findByIP(ip4) {
		t.Error("expected cannot find MACEntry ", mac1.String(), ip4)
	}
}

func Test_AddMany(t *testing.T) {

	tc := setupTestHandler(t)
	defer tc.Close()

	MACEntry, _ := tc.arp.virtual.upsert(StateNormal, mac1, ip4)
	MACEntry2, _ := tc.arp.virtual.upsert(StateNormal, mac2, ip2)
	MACEntry3, _ := tc.arp.virtual.upsert(StateNormal, mac3, ip3)

	tc.arp.virtual.printTable()
	if len(tc.arp.virtual.macTable) != 3 || MACEntry != tc.arp.virtual.findByMAC(mac1) || MACEntry != tc.arp.virtual.findByIP(ip4) {
		tc.arp.virtual.printTable()
		t.Error("expected cannot find MACEntry 3 ", len(tc.arp.virtual.macTable), mac3.String(), ip3)
	}
	if len(tc.arp.virtual.macTable) != 3 || MACEntry3 != tc.arp.virtual.findByMAC(mac3) || MACEntry3 != tc.arp.virtual.findByIP(ip3) {
		tc.arp.virtual.printTable()
		t.Error("expected cannot find MACEntry 3 ", len(tc.arp.virtual.macTable), mac3.String(), ip3)
	}
	if len(tc.arp.virtual.macTable) != 3 || MACEntry2 != tc.arp.virtual.findByMAC(mac2) || MACEntry2 != tc.arp.virtual.findByIP(ip2) {
		t.Error("expected cannot find MACEntry 2 ", mac2.String(), ip2)
	}

	tc.arp.virtual.delete(mac2)

	if len(tc.arp.virtual.macTable) != 2 || MACEntry3 != tc.arp.virtual.findByMAC(mac3) || MACEntry3 != tc.arp.virtual.findByIP(ip3) {
		t.Error("expected cannot find MACEntry 3 second", mac3.String(), ip3)
	}

	if len(tc.arp.virtual.macTable) != 2 || tc.arp.virtual.findByMAC(mac2) != nil || tc.arp.virtual.findByIP(ip2) != nil {
		t.Error("expected cannot find MACEntry 2 second", mac2.String(), ip2)
	}

	MACEntry2, _ = tc.arp.virtual.upsert(StateNormal, mac2, ip2)
	if len(tc.arp.virtual.macTable) != 3 || MACEntry2 != tc.arp.virtual.findByMAC(mac2) || MACEntry2 != tc.arp.virtual.findByIP(ip2) {
		tc.arp.virtual.printTable()
		t.Error("expected cannot find MACEntry 2 third", len(tc.arp.virtual.macTable), mac1.String(), ip4)
	}
}
func Test_Delete(t *testing.T) {
	tc := setupTestHandler(t)
	defer tc.Close()

	tc.arp.virtual.upsert(StateNormal, mac1, ip4)
	MACEntry2, _ := tc.arp.virtual.upsert(StateVirtualHost, newVirtualHardwareAddr(), ip2)
	tc.arp.virtual.upsert(StateNormal, mac3, ip3)

	if len(tc.arp.virtual.macTable) != 3 || MACEntry2 != tc.arp.virtual.findByMAC(MACEntry2.MAC) || MACEntry2 != tc.arp.virtual.findVirtualIP(ip2) {
		t.Error("expected cannot find MACEntry ", mac2.String(), ip2)
	}
	tc.arp.virtual.delete(MACEntry2.MAC)

	if len(tc.arp.virtual.macTable) != 2 || tc.arp.virtual.findByMAC(mac2) != nil || tc.arp.virtual.findByIP(ip2) != nil {
		t.Error("expected cannot find MACEntry ", mac2.String(), ip2)
	}

	MACEntry2, _ = tc.arp.virtual.upsert(StateNormal, mac2, ip2)
	if len(tc.arp.virtual.macTable) != 3 || MACEntry2 != tc.arp.virtual.findByMAC(mac2) || MACEntry2 != tc.arp.virtual.findByIP(ip2) {
		t.Error("expected cannot find MACEntry ", mac2.String(), ip2)
	}
	tc.arp.virtual.delete(mac3)

}

func Test_DuplicateIP(t *testing.T) {
	tc := setupTestHandler(t)
	defer tc.Close()

	e, _ := tc.arp.virtual.upsert(StateNormal, mac1, ip2)
	tc.arp.virtual.updateIP(e, ip3)
	if !e.IP().Equal(ip3) && len(e.IPs()) != 2 {
		t.Fatal("expected ip3 ", e.IP())
	}
	tc.arp.virtual.updateIP(e, ip2)
	if !e.IP().Equal(ip2) && len(e.IPs()) != 3 {
		t.Fatal("expected ip2-2 ", e.IP())
	}
	tc.arp.virtual.updateIP(e, ip4)
	if !e.IP().Equal(ip4) && len(e.IPs()) != 4 {
		t.Fatal("expected ip2 ", e.IP())
	}
	tc.arp.virtual.updateIP(e, ip5)
	if !e.IP().Equal(ip5) && len(e.IPs()) != 4 {
		t.Fatal("expected ip5 ", e.IP())
	}
	tc.arp.virtual.updateIP(e, ip2)
	if !e.IP().Equal(ip2) && len(e.IPs()) != 4 {
		t.Fatal("expected ip2-2 ", e.IP())
	}

	if !e.IPArray[0].IP.Equal(ip2) || !e.IPArray[1].IP.Equal(ip5) || !e.IPArray[2].IP.Equal(ip4) || !e.IPArray[3].IP.Equal(ip3) {
		t.Fatal("invalid IPs", e.IPs())
	}
}
func Test_HuntIP(t *testing.T) {
	tc := setupTestHandler(t)
	defer tc.Close()

	e, _ := tc.arp.virtual.upsert(StateNormal, mac1, ip2)
	tc.arp.virtual.updateIP(e, ip3)
	e.State = StateHunt

	tc.arp.virtual.updateIP(e, ip3)
	if !e.IP().Equal(ip3) && len(e.IPs()) != 2 {
		t.Fatal("expected ip3 ", e.IP())
	}
	tc.arp.virtual.updateIP(e, ip2)
	if !e.IP().Equal(ip3) && len(e.IPs()) != 2 {
		t.Fatal("expected ip2 ", e.IP())
	}
	tc.arp.virtual.updateIP(e, ip4)
	if !e.IP().Equal(ip4) && len(e.IPs()) != 3 {
		t.Fatal("expected ip4 ", e.IP())
	}
	tc.arp.virtual.updateIP(e, ip2)
	if !e.IP().Equal(ip4) && len(e.IPs()) != 3 {
		t.Fatal("expected ip2-2 ", e.IP())
	}
	tc.arp.virtual.updateIP(e, ip5)
	if !e.IP().Equal(ip5) && len(e.IPs()) != 4 {
		t.Fatal("expected ip5 ", e.IP())
	}
	tc.arp.virtual.updateIP(e, ip3)
	if !e.IP().Equal(ip3) && len(e.IPs()) != 4 {
		t.Fatal("expected ip3-2 ", e.IP())
	}

	if !e.IPArray[0].IP.Equal(ip5) || !e.IPArray[1].IP.Equal(ip4) || !e.IPArray[2].IP.Equal(ip3) || !e.IPArray[3].IP.Equal(ip2) {
		t.Fatal("invalid IPs", e.IPs())
	}

}

func Test_arpTable_deleteStaleIP(t *testing.T) {
	tc := setupTestHandler(t)
	defer tc.Close()

	e, _ := tc.arp.virtual.upsert(StateNormal, mac1, ip2)

	tc.arp.virtual.updateIP(e, ip3)
	tc.arp.virtual.updateIP(e, ip4)
	tc.arp.virtual.updateIP(e, ip5)
	if !e.IP().Equal(ip5) && len(e.IPs()) != 4 {
		t.Fatal("expected ip5 ", e.IP())
	}

	e1, _ := tc.arp.virtual.upsert(StateNormal, mac2, ip2)
	if !e1.IP().Equal(ip2) && len(e1.IPs()) != 1 {
		t.Fatal("expected ip2 ", e1.IPs())
	}
	if !e.IP().Equal(ip4) && len(e.IPs()) != 3 {
		t.Fatal("expected ip2 ", e.IPs())
	}

	tc.arp.virtual.updateIP(e1, ip5)
	tc.arp.virtual.updateIP(e1, ip4)
	tc.arp.virtual.updateIP(e1, ip3)
	if !e1.IP().Equal(ip3) && len(e1.IPs()) != 4 {
		t.Fatal("expected dup ip5 ", e1.IPs())
	}
	if !e.IP().Equal(ip5) && len(e.IPs()) != 1 {
		t.Fatal("expected dup ip5e ", e.IPs())
	}
}
