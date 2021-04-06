package test

import (
	"net"
	"testing"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	log "github.com/sirupsen/logrus"
)

func TestHandler_capture(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	log.SetLevel(log.DebugLevel)
	dhcp4.Debug = false
	packet.Debug = true
	arp.Debug = true

	tests := []TestEvent{}

	// MAC1 - capture after dhcp
	addr := packet.Addr{MAC: MAC1}
	tests = append(tests, NewHostEvents(addr, 1, 1)...)
	tests = append(tests, TestEvent{name: "capture-" + addr.MAC.String(), hostTableInc: 0, macTableInc: 0, responsePos: 0, responseTableInc: -1, // -1 means don't count
		waitTimeAfter: time.Millisecond * 10,
		action:        "capture", srcAddr: packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
	})
	tests = append(tests, NewHostEvents(addr, 1, 0)...) // get a second IP with captured net

	// MAC2 - capture before dhcp discover
	addr = packet.Addr{MAC: MAC2}
	tests = append(tests, TestEvent{name: "capture-" + addr.MAC.String(), hostTableInc: 0, macTableInc: 0, responsePos: 0, responseTableInc: -1, // -1 means don't count
		action: "capture", srcAddr: packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
	})
	tests = append(tests, NewHostEvents(addr, 1, 0)...)

	// capture MAC1 again
	addr = packet.Addr{MAC: MAC1}
	tests = append(tests, TestEvent{name: "capture-" + addr.MAC.String(), hostTableInc: 0, macTableInc: 0, responsePos: 0, responseTableInc: -1, // -1 means don't count
		waitTimeAfter: time.Millisecond * 10,
		action:        "capture", srcAddr: packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}
	checkOnlineCount(t, tc, 3, 1)
	checkCaptureCount(t, tc, 3, 2)
}

func TestHandler_captureDHCP(t *testing.T) {
	tc := NewTestContext()
	defer tc.Close()

	log.SetLevel(log.DebugLevel)
	dhcp4.Debug = false
	packet.Debug = true
	arp.Debug = true

	tests := []TestEvent{}

	// MAC1 - capture after dhcp
	addr := packet.Addr{MAC: MAC1}
	tests = append(tests, NewHostEvents(addr, 1, 1)...)
	tests = append(tests, TestEvent{name: "capture-" + addr.MAC.String(), hostTableInc: 0, macTableInc: 0, responsePos: 0, responseTableInc: -1, // -1 means don't count
		waitTimeAfter: time.Millisecond * 10,
		action:        "capture", srcAddr: packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
	})

	// tests = append(tests, NewHostEvents(addr, 1, 0)...) // get a second IP with captured net

	tests = append(tests, []TestEvent{
		{name: "discover2-" + addr.MAC.String(), action: "dhcp4Discover", hostTableInc: 0, macTableInc: 0, responsePos: -1, responseTableInc: -1,
			srcAddr:       packet.Addr{MAC: addr.MAC, IP: net.IPv4zero},
			wantHost:      nil, // don't validate host
			waitTimeAfter: time.Millisecond * 10,
		},
		{name: "request2-" + addr.MAC.String(), action: "dhcp4Request", hostTableInc: 1, macTableInc: 0, responsePos: -1, responseTableInc: -1,
			srcAddr:       packet.Addr{MAC: addr.MAC, IP: IP5}, // request different IP
			wantHost:      nil,
			waitTimeAfter: time.Millisecond * 20,
		},
		{name: "arp-probe2-" + addr.MAC.String(), action: "arpProbe", hostTableInc: 0, macTableInc: 0, responsePos: -1, responseTableInc: 0,
			srcAddr:       packet.Addr{MAC: addr.MAC, IP: IP5},
			wantHost:      nil,
			waitTimeAfter: time.Millisecond * 10,
		},
	}...)
	tests = append(tests, NewHostEvents(addr, 1, 0)...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAction(t, tc, tt)
		})

	}
	checkOnlineCount(t, tc, 2, 2)
	checkCaptureCount(t, tc, 3, 1)
}
