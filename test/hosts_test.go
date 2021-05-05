package test

import (
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
