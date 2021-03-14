package test

import (
	"testing"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	log "github.com/sirupsen/logrus"
)

func TestHandler_newHostSimple(t *testing.T) {
	tc := setupTestHandler()
	defer tc.Close()

	log.SetLevel(log.DebugLevel)
	dhcp4.Debug = true
	// packet.Debug = true
	// arp.Debug = true

	tests := newHostEvents(packet.Addr{MAC: mac1}, 1, 1)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}
}

func TestHandler_newHostMany(t *testing.T) {
	tc := setupTestHandler()
	defer tc.Close()

	packet.Debug = true
	arp.Debug = true

	tests := []testEvent{}
	tests = append(tests, newHostEvents(packet.Addr{MAC: mac1}, 1, 1)...)
	tests = append(tests, newHostEvents(packet.Addr{MAC: mac2}, 1, 1)...)
	tests = append(tests, newHostEvents(packet.Addr{MAC: mac3}, 1, 1)...)
	tests = append(tests, newHostEvents(packet.Addr{MAC: mac4}, 1, 1)...)
	tests = append(tests, newHostEvents(packet.Addr{MAC: mac5}, 1, 1)...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}
	checkOnlineCount(t, tc, 6, 0)
}

func TestHandler_sameHostMany(t *testing.T) {
	tc := setupTestHandler()
	defer tc.Close()

	packet.Debug = true
	arp.Debug = true

	tests := []testEvent{}
	tests = append(tests, newHostEvents(packet.Addr{MAC: mac1}, +1, 1)...)
	tests = append(tests, newHostEvents(packet.Addr{MAC: mac1}, +0, 0)...) // dhcp will reuse ip
	tests = append(tests, newHostEvents(packet.Addr{MAC: mac1}, +0, 0)...) // dhcp will reuse ip
	tests = append(tests, newHostEvents(packet.Addr{MAC: mac1}, +0, 0)...) // dhcp will reuse ip
	tests = append(tests, newHostEvents(packet.Addr{MAC: mac1}, +0, 0)...) // dhcp will reuse ip

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})
	}
	checkOnlineCount(t, tc, 2, 0)
	tc.packet.PrintTable()
}

func TestHandler_existingHost(t *testing.T) {
	tc := setupTestHandler()
	defer tc.Close()

	packet.Debug = true
	arp.Debug = true
	packet.DebugIP4 = true

	// tc.savedIP = ip2.To4()
	tests := []testEvent{}
	addr := packet.Addr{MAC: mac2, IP: ip1.To4()}
	tests = append(tests, newArpAnnoucementEvent(packet.Addr{MAC: addr.MAC, IP: addr.IP}, 1, 1)...)
	tests = append(tests, newHostEvents(packet.Addr{MAC: addr.MAC}, 1, 0)...) // will dhcp new host ip

	addr = packet.Addr{MAC: mac2, IP: ip5.To4()}
	tests = append(tests, newArpAnnoucementEvent(packet.Addr{MAC: addr.MAC, IP: addr.IP}, 1, 0)...)
	tests = append(tests, newHostEvents(packet.Addr{MAC: addr.MAC}, 0, 0)...) // dhcp will re-use previous still valid lease

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})
	}

	checkOnlineCount(t, tc, 2, 2)
}