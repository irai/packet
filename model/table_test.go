package model

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func setupTestHandler() *Handler {
	h := &Handler{LANHosts: newHostTable(), closeChan: make(chan bool)}
	h.MACTable = newMACTable(h)
	h.HandlerDHCP4 = PacketNOOP{}
	h.HandlerARP = PacketNOOP{}
	h.HandlerICMP4 = PacketNOOP{}
	h.HandlerICMP6 = PacketNOOP{}
	return h
}

func TestHandler_findOrCreateHostTestCopyIPMAC(t *testing.T) {
	bufIP := []byte{192, 168, 1, 1}
	ip := net.IPv4(192, 168, 1, 1)

	bufMAC := []byte{1, 1, 1, 2, 2, 2}
	mac := net.HardwareAddr{1, 1, 1, 2, 2, 2}

	engine := setupTestHandler()
	defer engine.Close()

	host, _ := engine.findOrCreateHost(net.HardwareAddr(bufMAC), net.IP(bufIP))
	engine.lockAndSetOnline(host, false)

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

	host, _ = engine.findOrCreateHost(net.HardwareAddr(bufMAC), net.IP(bufIP6))
	engine.lockAndSetOnline(host, false)
	bufIP6[8] = 0xff
	bufMAC[0] = 0x00
	if !host.IP.Equal(ip6) || !host.MACEntry.IP6GUA.Equal(ip6) {
		t.Error("findOrCreateHost wrong IP", host, host.MACEntry)
	}
	if !bytes.Equal(mac, host.MACEntry.MAC) {
		t.Error("findOrCreateHost wrong MAC", host, host.MACEntry)
	}

	if n := len(engine.LANHosts.Table); n != 2 {
		engine.printHostTable()
		t.Errorf("findOrCreateHost invalid len=%d want=%d ", n, 3)
	}
}

func Benchmark_findOrCreateHost(b *testing.B) {
	engine := setupTestHandler()
	defer engine.Close()

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

func TestHandler_findOrCreateHostDupIP(t *testing.T) {
	engine := setupTestHandler()
	defer engine.Close()

	Debug = true

	// First create host for IP3 and IP2 and set online
	host1, _ := engine.findOrCreateHost(mac1, ip3)
	engine.lockAndSetOnline(host1, true)
	host1, _ = engine.findOrCreateHost(mac1, ip2)
	host1.dhcp4Store.Name = "mac1" // test that name will clear - this was a bug in past
	engine.lockAndSetOnline(host1, true)
	engine.lockAndSetOnline(host1, false)
	if err := engine.Capture(mac1); err != nil {
		t.Fatal(err)
	}
	if !host1.MACEntry.Captured {
		t.Fatal("host not capture")
	}

	// new mac, same IP
	host2, _ := engine.findOrCreateHost(mac2, ip2)
	if host2.MACEntry.Captured { // mac should not be captured
		t.Fatal("host not capture")
	}
	if host2.dhcp4Store.Name != "" {
		t.Fatal("invalid host name")
	}

	// there must be two macs
	if n := len(engine.MACTable.Table); n != 2 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid mac table len=%d", n))
	}

	// The must only be two hosts for IP2
	if n := len(engine.LANHosts.Table); n != 2 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table len=%d ", n))
	}

	// second IPs
	host1, _ = engine.findOrCreateHost(mac2, ip2)
	if host1.MACEntry.Captured { // mac should not be captured
		t.Fatal("host not capture")
	}
}
