package engine

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/icmp"
)

func newSession() *packet.Session {
	// fake nicinfo
	nicInfo := &packet.NICInfo{
		HostMAC:   hostMAC,
		HostIP4:   net.IPNet{IP: hostIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterIP4: net.IPNet{IP: routerIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		HomeLAN4:  homeLAN,
		HostAddr4: packet.Addr{MAC: hostMAC, IP: hostIP4},
	}

	// TODO: fix this to discard writes like ioutil.Discard
	conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")

	session, _ := packet.Config{Conn: conn, NICInfo: nicInfo}.NewSession()
	return session
}

func setupTestHandler() *Handler {
	h := &Handler{}
	// no plugins to start
	h.ARPHandler = packet.PacketNOOP{}
	h.HandlerIP4 = packet.PacketNOOP{}
	h.HandlerIP6 = packet.PacketNOOP{}
	h.ARPHandler = packet.PacketNOOP{}
	h.ICMP4Handler = icmp.ICMP4NOOP{}
	h.ICMP6Handler = icmp.ICMP6NOOP{}
	h.DHCP4Handler = packet.PacketNOOP{}
	// h.session = &packet.Session{HostTable: packet.NewHostTable(), MACTable: packet.NewMACTable()}
	h.session = newSession()
	h.LayerTable = append(h.LayerTable, LayerProcessor{EtherType: 0x8808, Function: ProcessEthernetPause})
	h.LayerTable = append(h.LayerTable, LayerProcessor{EtherType: 0x8899, Function: ProcessRRCP})
	h.LayerTable = append(h.LayerTable, LayerProcessor{EtherType: 0x88cc, Function: ProcessLLDP})
	h.LayerTable = append(h.LayerTable, LayerProcessor{EtherType: 0x890d, Function: Process802_11r})
	h.LayerTable = append(h.LayerTable, LayerProcessor{EtherType: 0x893a, Function: ProcessIEEE1905})
	h.LayerTable = append(h.LayerTable, LayerProcessor{EtherType: 0x6970, Function: ProcessSonos})
	h.LayerTable = append(h.LayerTable, LayerProcessor{EtherType: 0x880a, Function: Process880a})

	return h
}

func TestHandler_findOrCreateHostDupIP(t *testing.T) {
	engine := setupTestHandler()

	packet.Debug = false

	// First create host with two IPs - IP3 and IP2 and set online
	addr := packet.Addr{MAC: mac1, IP: ip3}
	host1, _ := engine.session.FindOrCreateHost(addr)
	engine.session.SetOnline(host1)
	addr.IP = ip2
	host1, _ = engine.session.FindOrCreateHost(addr)
	host1.DHCP4Name.Name = "mac1" // test that name will clear - this was a previous bug
	engine.session.SetOnline(host1)

	// set host offline
	engine.session.SetOffline(host1)
	if err := engine.Capture(mac1); err != nil {
		t.Fatal(err)
	}
	if !host1.MACEntry.Captured {
		engine.session.PrintTable()
		t.Fatal("host not capture")
	}

	// new mac, same IP - Duplicated IP on network
	host2, _ := engine.session.FindOrCreateHost(packet.Addr{MAC: mac2, IP: ip2})
	if host2.MACEntry.Captured { // mac should not be captured
		engine.session.PrintTable()
		t.Fatal("host not capture")
	}
	// if host2.DHCP4Name.Name != "" {
	// t.Fatal("invalid host name")
	// }

	// there must be two macs
	if n := len(engine.session.MACTable.Table); n != 2 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid mac table len=%d", n))
	}

	// The must only be two hosts for IP2
	if n := len(engine.session.HostTable.Table); n != 2 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table len=%d ", n))
	}

	// second IPs
	host1, _ = engine.session.FindOrCreateHost(packet.Addr{MAC: mac2, IP: ip2})
	if host1.MACEntry.Captured { // mac should not be captured
		t.Fatal("host not capture")
	}
}

// TestHandler_anotherHostDHCP test the stage transition when dhcp is for another host
//
func TestHandler_anotherHostDHCP(t *testing.T) {
	engine := setupTestHandler()

	packet.Debug = false

	// First create host with two IPs - IP3 and IP2 and set online
	addr := packet.Addr{MAC: mac1, IP: ip3}
	host1, _ := engine.session.FindOrCreateHost(addr)
	engine.session.SetOnline(host1)
	if err := engine.Capture(mac1); err != nil {
		t.Fatal(err)
	}

	if !host1.MACEntry.Captured {
		engine.session.PrintTable()
		t.Fatal("host not captured")
	}
	if host1.HuntStage != packet.StageHunt {
		t.Fatalf("invalid stage=%v want=%v", host1.HuntStage, packet.StageHunt)
	}

	// simulate DHCP same host result
	result := packet.Result{}
	result.Update = true
	result.IsRouter = true // hack to mark result as a new host
	result.SrcAddr = addr  // same addr IP
	result.NameEntry.Name = "New name"
	result.HuntStage = packet.StageNoChange
	engine.lockAndProcessDHCP4Update(host1, result)
	// it is the same IP, stage should not change
	if host1.HuntStage != packet.StageHunt {
		t.Fatalf("invalid stage=%v want=%v", host1.HuntStage, packet.StageHunt)
	}

	if n := len(engine.session.MACTable.Table); n != 1 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid mac table len=%d", n))
	}
	if n := len(engine.session.HostTable.Table); n != 1 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table len=%d ", n))
	}
}

func TestHandler_Offline(t *testing.T) {
	engine := setupTestHandler()

	packet.Debug = true

	// First create host with two IPs - IP3 and IP2 and set online
	host1, _ := engine.session.FindOrCreateHost(packet.Addr{MAC: mac1, IP: ip3})
	engine.session.SetOnline(host1)
	host2, _ := engine.session.FindOrCreateHost(packet.Addr{MAC: mac1, IP: ip2})
	engine.session.SetOnline(host2)
	host3, _ := engine.session.FindOrCreateHost(packet.Addr{MAC: mac1, IP: ip6LLA1})
	engine.session.SetOnline(host3)
	host4, _ := engine.session.FindOrCreateHost(packet.Addr{MAC: mac1, IP: ip6GUA1})
	engine.session.SetOnline(host4)
	host5, _ := engine.session.FindOrCreateHost(packet.Addr{MAC: mac1, IP: ip6GUA2})
	engine.session.SetOnline(host5)
	host6, _ := engine.session.FindOrCreateHost(packet.Addr{MAC: mac1, IP: ip6GUA3})
	engine.session.SetOnline(host6)

	if n := len(engine.session.HostTable.Table); n != 6 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table len=%d ", n))
	}

	// capture
	if err := engine.Capture(mac1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond * 3)

	// set hosts offline
	engine.session.SetOffline(host1)
	engine.session.SetOffline(host2)
	engine.session.SetOffline(host3)
	engine.session.SetOffline(host4)
	engine.session.SetOffline(host5)
	engine.session.SetOffline(host6)

	if n := len(engine.session.HostTable.Table); n != 6 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table 2 len=%d ", n))
	}

	engine.purge(time.Now().Add(time.Hour), time.Second*5, time.Minute*5, time.Minute*30)
	if n := len(engine.session.HostTable.Table); n != 0 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table 2 len=%d ", n))
	}
	engine.PrintTable()
}
