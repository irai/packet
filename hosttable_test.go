package packet

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

var (
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	ip1     = net.IPv4(192, 168, 0, 1)
	ip2     = net.IPv4(192, 168, 0, 2)
	ip3     = net.IPv4(192, 168, 0, 3)
	ip4     = net.IPv4(192, 168, 0, 4)
	ip5     = net.IPv4(192, 168, 0, 5)

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

	ip6LLARouter = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLAHost   = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x10}
	ip6LLA1      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6LLA2      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	ip6LLA3      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03}
	ip6LLA4      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04}
	ip6LLA5      = net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05}

	hostAddr   = Addr{MAC: hostMAC, IP: hostIP4}
	routerAddr = Addr{MAC: routerMAC, IP: routerIP4}

	dnsIP4 = net.IPv4(8, 8, 8, 8)
)

func setupTestHandler() *Session {
	h := NewEmptySession()
	return h
}

func TestHandler_findOrCreateHostTestCopyIPMAC(t *testing.T) {
	bufIP := []byte{192, 168, 1, 1}
	ip := net.IPv4(192, 168, 1, 1)

	bufMAC := []byte{1, 1, 1, 2, 2, 2}
	mac := net.HardwareAddr{1, 1, 1, 2, 2, 2}

	session := setupTestHandler()

	host, _ := session.findOrCreateHost(net.HardwareAddr(bufMAC), net.IP(bufIP))
	// engine.lockAndSetOnline(host, false)

	bufIP[0] = 0xff
	bufMAC[0] = 0x00

	// must update host and mac entry ip
	if !host.IP.Equal(ip) || !host.MACEntry.IP4.Equal(ip) {
		session.printHostTable()
		t.Error("findOrCreateHost wrong IP", host, host.MACEntry)
	}
	if !bytes.Equal(mac, host.MACEntry.MAC) {
		t.Error("findOrCreateHost wrong MAC", host, host.MACEntry)
	}

	bufMAC = []byte{1, 1, 1, 2, 2, 2}
	bufIP6 := []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6 := net.IP{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	host, _ = session.findOrCreateHost(net.HardwareAddr(bufMAC), net.IP(bufIP6))
	// engine.lockAndSetOnline(host, false)
	bufIP6[8] = 0xff
	bufMAC[0] = 0x00
	if !host.IP.Equal(ip6) || !host.MACEntry.IP6GUA.Equal(ip6) {
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
		host, _ := engine.findOrCreateHost(mac, ip)
		if host.IP.Equal(net.IPv4zero) {
			fmt.Println("invalid host")
		}
	}
}
