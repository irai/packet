package engine

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	"github.com/irai/packet/icmp"
)

func newSession() *packet.Session {
	// fake nicinfo
	nicInfo := &packet.NICInfo{
		HostMAC:     hostMAC,
		HostIP4:     net.IPNet{IP: hostIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterIP4:   net.IPNet{IP: routerIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		HomeLAN4:    homeLAN,
		HostAddr4:   packet.Addr{MAC: hostMAC, IP: hostIP4},
		RouterAddr4: packet.Addr{MAC: routerMAC, IP: routerIP4},
	}

	// TODO: fix this to discard writes like ioutil.Discard
	conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")

	session, _ := packet.Config{Conn: conn, NICInfo: nicInfo}.NewSession()
	return session
}

func setupTestHandler() *Handler {
	h := &Handler{}
	// no plugins to start
	h.ARPHandler = arp.ARPNOOP{}
	h.HandlerIP4 = packet.PacketNOOP{}
	h.HandlerIP6 = packet.PacketNOOP{}
	h.ICMP4Handler = icmp.ICMP4NOOP{}
	h.ICMP6Handler = icmp.ICMP6NOOP{}
	h.DHCP4Handler = dhcp4.PacketNOOP{}
	// h.session = &packet.Session{HostTable: packet.NewHostTable(), MACTable: packet.NewMACTable()}
	h.session = newSession()

	return h
}

func TestHandler_findOrCreateHostDupIP(t *testing.T) {
	engine := setupTestHandler()

	packet.Debug = false

	// First create host with two IPs - IP3 and IP2 and set online
	addr := packet.Addr{MAC: mac1, IP: ip3}
	frame1 := newTestHost(engine.session, addr)
	engine.session.SetOnline(frame1)
	addr.IP = ip2
	frame1 = newTestHost(engine.session, addr)
	frame1.Host.DHCP4Name.Name = "mac1" // test that name will clear - this was a previous bug
	engine.session.SetOnline(frame1)

	// set host offline
	engine.session.SetOffline(frame1.Host)
	if err := engine.Capture(mac1); err != nil {
		t.Fatal(err)
	}
	if !frame1.Host.MACEntry.Captured {
		engine.session.PrintTable()
		t.Fatal("host not capture")
	}

	// new mac, same IP - Duplicated IP on network
	host2 := newTestHost(engine.session, packet.Addr{MAC: mac2, IP: ip2})
	if host2.Host.MACEntry.Captured { // mac should not be captured
		engine.session.PrintTable()
		t.Fatal("host not capture")
	}
	// if host2.DHCP4Name.Name != "" {
	// t.Fatal("invalid host name")
	// }

	// there must be four macs
	if n := len(engine.session.MACTable.Table); n != 4 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid mac table len=%d", n))
	}

	// The must only be four hosts for IP2
	if n := len(engine.session.HostTable.Table); n != 4 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table len=%d ", n))
	}

	// second IPs
	frame1 = newTestHost(engine.session, packet.Addr{MAC: mac2, IP: ip2})
	if frame1.Host.MACEntry.Captured { // mac should not be captured
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
	frame1 := newTestHost(engine.session, addr)
	engine.session.SetOnline(frame1)
	if err := engine.Capture(mac1); err != nil {
		t.Fatal(err)
	}

	if !frame1.Host.MACEntry.Captured {
		engine.session.PrintTable()
		t.Fatal("host not captured")
	}
	if frame1.Host.HuntStage != packet.StageHunt {
		t.Fatalf("invalid stage=%v want=%v", frame1.Host.HuntStage, packet.StageHunt)
	}

	// simulate DHCP same host result
	result := packet.Result{}
	result.Update = true
	result.IsRouter = true // hack to mark result as a new host
	result.SrcAddr = addr  // same addr IP
	result.NameEntry.Name = "New name"
	result.HuntStage = packet.StageNoChange
	engine.lockAndProcessDHCP4Update(frame1.Host, result)
	// it is the same IP, stage should not change
	if frame1.Host.HuntStage != packet.StageHunt {
		t.Fatalf("invalid stage=%v want=%v", frame1.Host.HuntStage, packet.StageHunt)
	}

	if n := len(engine.session.MACTable.Table); n != 3 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid mac table len=%d", n))
	}
	if n := len(engine.session.HostTable.Table); n != 3 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table len=%d ", n))
	}
}

func TestHandler_Offline(t *testing.T) {
	engine := setupTestHandler()

	packet.Debug = true

	// First create host with two IPs - IP3 and IP2 and set online
	frame1 := newTestHost(engine.session, packet.Addr{MAC: mac1, IP: ip3})
	engine.session.SetOnline(frame1)
	frame2 := newTestHost(engine.session, packet.Addr{MAC: mac1, IP: ip2})
	engine.session.SetOnline(frame2)
	frame3 := newTestHost(engine.session, packet.Addr{MAC: mac1, IP: ip6LLA1})
	engine.session.SetOnline(frame3)
	frame4 := newTestHost(engine.session, packet.Addr{MAC: mac1, IP: ip6GUA1})
	engine.session.SetOnline(frame4)
	frame5 := newTestHost(engine.session, packet.Addr{MAC: mac1, IP: ip6GUA2})
	engine.session.SetOnline(frame5)
	frame6 := newTestHost(engine.session, packet.Addr{MAC: mac1, IP: ip6GUA3})
	engine.session.SetOnline(frame6)

	if n := len(engine.session.HostTable.Table); n != 8 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table len=%d ", n))
	}

	// capture
	if err := engine.Capture(mac1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond * 3)

	// set hosts offline
	engine.session.SetOffline(frame1.Host)
	engine.session.SetOffline(frame2.Host)
	engine.session.SetOffline(frame3.Host)
	engine.session.SetOffline(frame4.Host)
	engine.session.SetOffline(frame5.Host)
	engine.session.SetOffline(frame6.Host)

	if n := len(engine.session.HostTable.Table); n != 8 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table 2 len=%d ", n))
	}

	engine.purge(time.Now().Add(time.Hour), time.Second*5, time.Minute*5, time.Minute*30)
	if n := len(engine.session.HostTable.Table); n != 2 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table 2 len=%d ", n))
	}
	engine.PrintTable()
}
