package packet

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

var (
	// zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	ip1 = net.IPv4(192, 168, 0, 1)
	ip2 = net.IPv4(192, 168, 0, 2)
	ip3 = net.IPv4(192, 168, 0, 3)
	ip4 = net.IPv4(192, 168, 0, 4)
	ip5 = net.IPv4(192, 168, 0, 5)

	localIP  = net.IPv4(169, 254, 0, 10).To4()
	localIP2 = net.IPv4(169, 254, 0, 11).To4()

	hostMAC   = net.HardwareAddr{0x00, 0x55, 0x55, 0x55, 0x55, 0x55}
	hostIP4   = net.IPv4(192, 168, 0, 129).To4()
	routerMAC = net.HardwareAddr{0x00, 0x66, 0x66, 0x66, 0x66, 0x66}
	routerIP4 = net.IPv4(192, 168, 0, 11).To4()
	homeLAN   = net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}

	mac1 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5 = net.HardwareAddr{0x00, 0x02, 0x03, 0x04, 0x05, 0x05}

	addr1 = Addr{MAC: mac1, IP: ip1}
	addr2 = Addr{MAC: mac2, IP: ip2}
	addr3 = Addr{MAC: mac3, IP: ip3}
	addr4 = Addr{MAC: mac4, IP: ip4}

	// ip6LLARouter = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLAHost = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x10}
	// ip6LLA1      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLA2 = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	// ip6LLA3      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03}
	ip6LLA4 = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04}
	// ip6LLA5      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05}

	hostAddr   = Addr{MAC: hostMAC, IP: hostIP4}
	routerAddr = Addr{MAC: routerMAC, IP: routerIP4}

	// dnsIP4 = net.IPv4(8, 8, 8, 8)
)

func setupTestHandler() *Session {
	h := testSession()
	return h
}

func TestHandler_findOrCreateHostTestCopyIPMAC(t *testing.T) {
	bufIP := []byte{192, 168, 1, 1}
	ip := CopyIP(net.IP(bufIP).To4())

	bufMAC := []byte{1, 1, 1, 2, 2, 2}
	mac := net.HardwareAddr{1, 1, 1, 2, 2, 2}

	session := setupTestHandler()

	host, _ := session.findOrCreateHost(Addr{MAC: net.HardwareAddr(bufMAC), IP: net.IP(bufIP)})
	bufIP[0] = 0xff
	bufMAC[0] = 0x00
	if !host.Addr.IP.Equal(ip) {
		session.printHostTable()
		t.Error("findOrCreateHost wrong IP", host, host.MACEntry)
	}
	if !bytes.Equal(mac, host.MACEntry.MAC) {
		t.Error("findOrCreateHost wrong MAC", host, host.MACEntry)
	}

	bufMAC = []byte{1, 1, 1, 2, 2, 2}
	bufIP6 := []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6 := CopyIP(net.IP(bufIP6))

	host, _ = session.findOrCreateHost(Addr{MAC: net.HardwareAddr(bufMAC), IP: net.IP(bufIP6)})
	bufIP6[8] = 0xff
	bufMAC[0] = 0x00
	if !host.Addr.IP.Equal(ip6) {
		t.Error("findOrCreateHost wrong IP", host, host.MACEntry)
	}
	if !bytes.Equal(mac, host.MACEntry.MAC) {
		t.Error("findOrCreateHost wrong MAC", host, host.MACEntry)
	}

	if n := len(session.HostTable.Table); n != 2 {
		session.printHostTable()
		t.Errorf("findOrCreateHost invalid len=%d want=%d ", n, 3)
	}
}

func Benchmark_findOrCreateHost(b *testing.B) {
	engine := setupTestHandler()

	// March 2021 - running benchmark on WSL 2 - 64 hosts
	// Benchmark_findOrCreateHost-8   	 7318504	       145 ns/op	       0 B/op	       0 allocs/op
	// Benchmark_findOrCreateHost-8   	 7555534	       141 ns/op	       0 B/op	       0 allocs/op
	ip := CopyIP(hostIP4).To4()
	mac := net.HardwareAddr{0x00, 0xff, 0xaa, 0xbb, 0x55, 0x55}
	for i := 0; i < b.N; i++ {
		ip[3] = byte(i % 64)
		mac[5] = byte(i % 64)
		host, _ := engine.findOrCreateHost(Addr{MAC: mac, IP: ip})
		if host.Addr.IP.Equal(net.IPv4zero) {
			fmt.Println("invalid host")
		}
	}
}

func TestHost_UpdateMDNSName(t *testing.T) {
	session := setupTestHandler()
	host1, _ := session.findOrCreateHost(Addr{MAC: mac1, IP: ip1})
	session.SetOnline(host1) // first notification
	name := NameEntry{Type: "MDNS", Name: "abc", Model: "android"}
	host1.UpdateMDNSName(name)
	session.SetOnline(host1) // change of name notification
	var notification Notification
	for i := 0; i < 2; i++ { // must get have 2 notifications - online and change of name
		select {
		case notification = <-session.C:
		case <-time.After(time.Second):
			t.Fatal("did not receive notification number", i)
		}
	}
	if notification.MDNSName.Name != name.Name || notification.MDNSName.Model != name.Model {
		t.Error("unexpected name", notification.MDNSName)
	}
}

func TestHost_UpdateLLMNRName(t *testing.T) {
	session := setupTestHandler()
	host1, _ := session.findOrCreateHost(Addr{MAC: mac1, IP: ip1})
	session.SetOnline(host1) // first notification
	name := NameEntry{Type: "LLMNR", Name: "abc", Model: "android"}
	host1.UpdateLLMNRName(name)
	session.SetOnline(host1) // change of name notification
	var notification Notification
	for i := 0; i < 2; i++ { // must get have 2 notifications - online and change of name
		select {
		case notification = <-session.C:
		case <-time.After(time.Second):
			t.Fatal("did not receive notification number", i)
		}
	}
	if notification.LLMNRName.Name != name.Name || notification.LLMNRName.Model != name.Model {
		t.Error("unexpected name", notification.LLMNRName)
	}
}

func TestHost_UpdateSSDPName(t *testing.T) {
	session := setupTestHandler()
	host1, _ := session.findOrCreateHost(Addr{MAC: mac1, IP: ip1})
	session.SetOnline(host1) // first notification
	name := NameEntry{Type: "SSDP", Name: "abc", Model: "android"}
	host1.UpdateSSDPName(name)
	session.SetOnline(host1) // change of name notification
	var notification Notification
	for i := 0; i < 2; i++ { // must get have 2 notifications - online and change of name
		select {
		case notification = <-session.C:
		case <-time.After(time.Second):
			t.Fatal("did not receive notification number", i)
		}
	}
	if notification.SSDPName.Name != name.Name || notification.SSDPName.Model != name.Model {
		t.Error("unexpected name", notification.SSDPName)
	}
}

func TestHost_UpdateNBNSName(t *testing.T) {
	session := setupTestHandler()
	host1, _ := session.findOrCreateHost(Addr{MAC: mac1, IP: ip1})
	session.SetOnline(host1) // first notification
	name := NameEntry{Type: "NBNS", Name: "abc", Model: "android"}
	host1.UpdateNBNSName(name)
	session.SetOnline(host1) // change of name notification
	var notification Notification
	for i := 0; i < 2; i++ { // must get have 2 notifications - online and change of name
		select {
		case notification = <-session.C:
		case <-time.After(time.Second):
			t.Fatal("did not receive notification number", i)
		}
	}
	if notification.NBNSName.Name != name.Name || notification.NBNSName.Model != name.Model {
		t.Error("unexpected name", notification.NBNSName)
	}
}
