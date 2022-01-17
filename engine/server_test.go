package engine

import (
	"fmt"
	"net"
	"testing"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	"github.com/irai/packet/icmp"
)

func newSession() *packet.Session {
	// fake nicinfo
	nicInfo := &packet.NICInfo{
		HomeLAN4:    homeLAN,
		HostAddr4:   packet.Addr{MAC: hostMAC, IP: hostIP4},
		RouterAddr4: packet.Addr{MAC: routerMAC, IP: routerIP4},
	}

	// TODO: fix this to discard writes like ioutil.Discard
	conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")

	session, _ := packet.Config{Conn: conn, NICInfo: nicInfo}.NewSession("")
	return session
}

func setupTestHandler() *Handler {
	h := &Handler{}
	// no plugins to start
	h.ARPHandler = arp.ARPNOOP{}
	h.ICMP4Handler = icmp.ICMP4NOOP{}
	h.ICMP6Handler = icmp.ICMP6NOOP{}
	h.DHCP4Handler = dhcp4.PacketNOOP{}
	// h.session = &packet.Session{HostTable: packet.NewHostTable(), MACTable: packet.NewMACTable()}
	h.session = newSession()

	return h
}

// TestHandler_anotherHostDHCP test the stage transition when dhcp is for another host
//
func TestHandler_anotherHostDHCP(t *testing.T) {
	engine := setupTestHandler()

	packet.Debug = false

	// First create host with two IPs - IP3 and IP2 and set online
	addr := packet.Addr{MAC: mac1, IP: ip3}
	frame1 := newTestHost(engine.session, addr)
	engine.session.Notify(frame1)
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
