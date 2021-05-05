package test

import (
	"fmt"
	"testing"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	"github.com/irai/packet/model"
	log "github.com/sirupsen/logrus"
)

func TestHandler_newHostSimple(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	log.SetLevel(log.DebugLevel)
	dhcp4.Debug = true
	packet.Debug = true
	// arp.Debug = true

	tests := NewHostEvents(model.Addr{MAC: MAC1}, "mac1", 1, 1)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}
}

func TestHandler_newHostMany(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	packet.Debug = true
	arp.Debug = true

	tests := []TestEvent{}
	tests = append(tests, NewHostEvents(model.Addr{MAC: MAC1}, "mac1", 1, 1)...)
	tests = append(tests, NewHostEvents(model.Addr{MAC: MAC2}, "mac2", 1, 1)...)
	tests = append(tests, NewHostEvents(model.Addr{MAC: MAC3}, "mac3", 1, 1)...)
	tests = append(tests, NewHostEvents(model.Addr{MAC: MAC4}, "mac4", 1, 1)...)
	tests = append(tests, NewHostEvents(model.Addr{MAC: MAC5}, "mac5", 1, 1)...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}
	checkOnlineCount(t, tc, 7, 0)
}

func TestHandler_sameHostMany(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	packet.Debug = true
	arp.Debug = true

	tests := []TestEvent{}
	tests = append(tests, NewHostEvents(model.Addr{MAC: MAC1}, "mac1", +1, 1)...)
	tests = append(tests, NewHostEvents(model.Addr{MAC: MAC1}, "mac1", +0, 0)...) // dhcp will reuse ip
	tests = append(tests, NewHostEvents(model.Addr{MAC: MAC1}, "mac1", +0, 0)...) // dhcp will reuse ip
	tests = append(tests, NewHostEvents(model.Addr{MAC: MAC1}, "mac1", +0, 0)...) // dhcp will reuse ip
	tests = append(tests, NewHostEvents(model.Addr{MAC: MAC1}, "mac1", +0, 0)...) // dhcp will reuse ip

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})
	}
	checkOnlineCount(t, tc, 3, 0)
	tc.Engine.PrintTable()
}

func TestHandler_existingHost(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	packet.Debug = true
	arp.Debug = true
	packet.DebugIP4 = true

	// tc.savedIP = ip2.To4()
	tests := []TestEvent{}
	addr := model.Addr{MAC: MAC2, IP: IP1.To4()}
	tests = append(tests, newArpAnnoucementEvent(model.Addr{MAC: addr.MAC, IP: addr.IP}, 1, 1)...)
	tests = append(tests, NewHostEvents(model.Addr{MAC: addr.MAC}, "mac2", 1, 0)...) // will dhcp new host ip

	addr = model.Addr{MAC: MAC2, IP: IP5.To4()}
	tests = append(tests, newArpAnnoucementEvent(model.Addr{MAC: addr.MAC, IP: addr.IP}, 1, 0)...)
	tests = append(tests, NewHostEvents(model.Addr{MAC: addr.MAC}, "mac2", 0, 0)...) // dhcp will re-use previous still valid lease

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})
	}

	checkOnlineCount(t, tc, 3, 2)
}

func TestHandler_findOrCreateHostDupIP(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	packet.Debug = true

	// First create host for IP3 and IP2 and set online
	host1, _ := tc.engine.Session().FindOrCreateHost(mac1, ip3)
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
	if n := len(engine.HostTable.Table); n != 2 {
		engine.PrintTable()
		t.Fatal(fmt.Sprintf("invalid host table len=%d ", n))
	}

	// second IPs
	host1, _ = engine.findOrCreateHost(mac2, ip2)
	if host1.MACEntry.Captured { // mac should not be captured
		t.Fatal("host not capture")
	}
}
