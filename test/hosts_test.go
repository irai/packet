package test

import (
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
)

func TestHandler_newHostSimple(t *testing.T) {
	tc := setupTestHandler()
	defer tc.Close()

	packet.Debug = true
	arp.Debug = true

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
}

func TestHandler_existingHost(t *testing.T) {
	tc := setupTestHandler()
	defer tc.Close()

	packet.Debug = true
	arp.Debug = true
	packet.DebugIP4 = true

	tc.savedIP = ip2.To4()
	addr := packet.Addr{MAC: mac2, IP: ip2}
	tests := []testEvent{
		{name: "arp-announcement-" + addr.MAC.String(), action: "arpAnnouncement", hostTableInc: 1, macTableInc: 1, responsePos: -1, responseTableInc: 0,
			srcAddr:       addr,
			wantHost:      &packet.Host{IP: addr.IP, Online: true},
			waitTimeAfter: time.Millisecond * 10,
		},
	}
	tests = append(tests, newHostEvents(packet.Addr{MAC: addr.MAC}, 1, 0)...) // will dhcp new host ip

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}
}
