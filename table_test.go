package packet

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestHandler_findOrCreateHostTestCopyIPMAC(t *testing.T) {
	bufIP := []byte{192, 168, 1, 1}
	ip := net.IPv4(192, 168, 1, 1)

	bufMAC := []byte{1, 1, 1, 2, 2, 2}
	mac := net.HardwareAddr{1, 1, 1, 2, 2, 2}

	tc := setupTestHandler()
	defer tc.Close()

	host, _ := tc.packet.findOrCreateHost(net.HardwareAddr(bufMAC), net.IP(bufIP))
	tc.packet.lockAndSetOnline(host, false)

	bufIP[0] = 0xff
	bufMAC[0] = 0x00

	// must update host and mac entry ip
	if !host.IP.Equal(ip) || !host.MACEntry.IP4.Equal(ip) {
		t.Error("findOrCreateHost wrong IP", host, host.MACEntry)
	}
	if !bytes.Equal(mac, host.MACEntry.MAC) {
		t.Error("findOrCreateHost wrong MAC", host, host.MACEntry)
	}

	bufMAC = []byte{1, 1, 1, 2, 2, 2}
	bufIP6 := []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ip6 := net.IP{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	host, _ = tc.packet.findOrCreateHost(net.HardwareAddr(bufMAC), net.IP(bufIP6))
	tc.packet.lockAndSetOnline(host, false)
	bufIP6[8] = 0xff
	bufMAC[0] = 0x00
	if !host.IP.Equal(ip6) || !host.MACEntry.IP6GUA.Equal(ip6) {
		t.Error("findOrCreateHost wrong IP", host, host.MACEntry)
	}
	if !bytes.Equal(mac, host.MACEntry.MAC) {
		t.Error("findOrCreateHost wrong MAC", host, host.MACEntry)
	}

	if len(tc.packet.LANHosts.Table) != 3 {
		tc.packet.printHostTable()
		t.Error("findOrCreateHost invalid leng ")
	}
}

func Benchmark_findOrCreateHost(b *testing.B) {
	tc := setupTestHandler()
	defer tc.Close()

	// March 2021 - running benchmark on WSL 2 - 64 hosts
	// Benchmark_findOrCreateHost-8   	 7318504	       145 ns/op	       0 B/op	       0 allocs/op
	// Benchmark_findOrCreateHost-8   	 7555534	       141 ns/op	       0 B/op	       0 allocs/op
	ip := CopyIP(hostIP4).To4()
	mac := net.HardwareAddr{0x00, 0xff, 0xaa, 0xbb, 0x55, 0x55}
	for i := 0; i < b.N; i++ {
		ip[3] = byte(i % 64)
		mac[5] = byte(i % 64)
		host, _ := tc.packet.findOrCreateHost(mac, ip)
		if host.IP.Equal(net.IPv4zero) {
			fmt.Println("invalid host")
		}
	}
}
